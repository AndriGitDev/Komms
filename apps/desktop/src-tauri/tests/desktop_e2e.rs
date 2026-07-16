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

use base64::Engine;
use komms_desktop::commands;
use komms_desktop::session::{
    hex_decode, NetworkSettings, Session, UiCustomIconCrop, UiCustomIconTarget, UiEvent,
    UiFolderSelection, UiFolderTarget, UiHint, UiImageCrop, UiImageEditRecipe, UiImageRegion,
    UiLabelTarget, UiMentionSpan, UiPinTarget, UiTextFormatHighlight, UiThemePreference,
};
use kult_ffi::{
    edit_image, ImageCrop, ImageEditRecipe, ImageEditRegion, ImageEditRegionKind, KdfChoice,
};

fn image_recipe() -> (UiImageEditRecipe, ImageEditRecipe) {
    (
        UiImageEditRecipe {
            crop: Some(UiImageCrop {
                x: 1,
                y: 0,
                width: 23,
                height: 16,
            }),
            rotation_quarter_turns: 1,
            regions: vec![
                UiImageRegion {
                    kind: "pixelate".to_owned(),
                    x: 0,
                    y: 0,
                    width: 8,
                    height: 8,
                    strength: 4,
                },
                UiImageRegion {
                    kind: "blur".to_owned(),
                    x: 8,
                    y: 0,
                    width: 8,
                    height: 12,
                    strength: 2,
                },
            ],
        },
        ImageEditRecipe {
            crop: Some(ImageCrop {
                x: 1,
                y: 0,
                width: 23,
                height: 16,
            }),
            rotation_quarter_turns: 1,
            regions: vec![
                ImageEditRegion {
                    kind: ImageEditRegionKind::Pixelate,
                    x: 0,
                    y: 0,
                    width: 8,
                    height: 8,
                    strength: 4,
                },
                ImageEditRegion {
                    kind: ImageEditRegionKind::Blur,
                    x: 8,
                    y: 0,
                    width: 8,
                    height: 12,
                    strength: 2,
                },
            ],
        },
    )
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

fn native_audio_with_metadata(canonical: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(canonical.len() + 12);
    bytes.extend_from_slice(b"RIFF");
    bytes.extend_from_slice(&((canonical.len() + 4) as u32).to_le_bytes());
    bytes.extend_from_slice(&canonical[8..36]);
    bytes.extend_from_slice(b"LIST\x04\0\0\0leak");
    bytes.extend_from_slice(&canonical[36..]);
    bytes
}

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

    fn count(&self, pred: impl Fn(&UiEvent) -> bool) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|event| pred(event))
            .count()
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

#[test]
fn desktop_text_formatting_matches_shared_corpus_and_uses_inert_dom_only() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../fixtures/b9-text-formatting-parity.json"
    ))
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let session = open(directory.path(), "text-formatting", &Events::default());
    for case in fixture["cases"].as_array().unwrap() {
        let highlights = case["highlights"]
            .as_array()
            .unwrap()
            .iter()
            .map(|highlight| UiTextFormatHighlight {
                start: highlight["start"].as_u64().unwrap() as u32,
                end: highlight["end"].as_u64().unwrap() as u32,
            })
            .collect();
        let formatted = session
            .format_text(case["source"].as_str().unwrap().to_owned(), highlights)
            .unwrap();
        assert_eq!(formatted.source, case["source"].as_str().unwrap());
        assert_eq!(formatted.plain_text, case["plain_text"].as_str().unwrap());
        assert_eq!(
            formatted.used_fallback,
            case["used_fallback"].as_bool().unwrap()
        );
        assert_eq!(
            formatted
                .blocks
                .iter()
                .map(|block| block.kind.as_str())
                .collect::<Vec<_>>(),
            case["block_kinds"]
                .as_array()
                .unwrap()
                .iter()
                .map(|kind| kind.as_str().unwrap())
                .collect::<Vec<_>>()
        );
    }
    let frontend = include_str!("../../ui/main.js");
    assert!(frontend.contains("appendFormattedBody"));
    assert!(frontend.contains("document.createTextNode(run.text)"));
    assert!(frontend.contains("formatted.plain_text"));
    let formatter = frontend
        .split("function styledRun")
        .nth(1)
        .unwrap()
        .split("async function refreshGroups")
        .next()
        .unwrap();
    assert!(!formatter.contains("innerHTML"));
    assert!(!formatter.contains(".src ="));
    assert!(!formatter.contains(".href ="));

    let android =
        include_str!("../../../android/app/src/main/kotlin/komms/android/TextFormatting.kt");
    assert!(android.contains("output.toString() == formatted.plainText"));
    assert!(!android.contains("URLSpan"));
    for source in [
        include_str!("../../../android/app/src/main/kotlin/komms/android/ChatActivity.kt"),
        include_str!("../../../android/app/src/main/kotlin/komms/android/GroupChatActivity.kt"),
        include_str!("../../../android/app/src/main/kotlin/komms/android/NoteToSelfActivity.kt"),
        include_str!("../../../android/app/src/main/kotlin/komms/android/ScheduledMessageUi.kt"),
    ] {
        assert!(source.contains("showFormattedText"));
    }
    let swift_renderer = include_str!("../../../ios/KommsApp/Sources/FormattedTextView.swift");
    assert!(swift_renderer.contains("formatted.plainText"));
    assert!(!swift_renderer.contains("NSDataDetector"));
    for source in [
        include_str!("../../../ios/KommsApp/Sources/ChatView.swift"),
        include_str!("../../../ios/KommsApp/Sources/GroupChatView.swift"),
        include_str!("../../../ios/KommsApp/Sources/NoteToSelfView.swift"),
        include_str!("../../../ios/KommsApp/Sources/ScheduledMessageView.swift"),
    ] {
        assert!(source.contains("FormattedTextView"));
    }
    session.stop();
}

#[test]
fn desktop_private_contact_rename_is_normalized_warned_duplicate_capable_and_durable() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../fixtures/b5-contact-rename-parity.json"
    ))
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let events = Events::default();
    let mut alice = open(directory.path(), "contact-rename-alice", &events);
    let bob = open(directory.path(), "contact-rename-bob", &Events::default());
    alice
        .add_contact(
            fixture["duplicate_name"].as_str().unwrap().to_owned(),
            &alice.my_bundle().unwrap().hex,
            &[],
        )
        .unwrap();
    let bob_peer = alice
        .add_contact("Bob".to_owned(), &bob.my_bundle().unwrap().hex, &[])
        .unwrap();
    let queued_before = alice.status().unwrap().queued;

    let normalized = alice
        .rename_contact(
            bob_peer.clone(),
            fixture["decomposed_name"].as_str().unwrap().to_owned(),
            false,
        )
        .unwrap();
    assert_eq!(
        normalized.normalized_name,
        fixture["normalized_name"].as_str().unwrap()
    );
    assert!(normalized.changed_by_normalization);
    let duplicate = alice
        .assess_contact_name(
            bob_peer.clone(),
            fixture["duplicate_name"].as_str().unwrap().to_owned(),
        )
        .unwrap();
    assert_eq!(duplicate.duplicate_count, 1);
    assert_eq!(duplicate.warnings, ["duplicate_name"]);
    assert!(alice
        .rename_contact(
            bob_peer.clone(),
            fixture["duplicate_name"].as_str().unwrap().to_owned(),
            false,
        )
        .is_err());
    alice
        .rename_contact(
            bob_peer.clone(),
            fixture["duplicate_name"].as_str().unwrap().to_owned(),
            true,
        )
        .unwrap();
    assert_eq!(
        alice
            .contacts()
            .unwrap()
            .into_iter()
            .filter(|contact| contact.name == fixture["duplicate_name"].as_str().unwrap())
            .count(),
        2
    );
    events.wait("contact renamed", |event| {
        matches!(event, UiEvent::ContactRenamed { peer, name }
            if peer == &bob_peer && name == fixture["duplicate_name"].as_str().unwrap())
    });
    assert_eq!(alice.status().unwrap().queued, queued_before);
    alice.stop();

    alice = open(directory.path(), "contact-rename-alice", &Events::default());
    assert_eq!(
        alice
            .contacts()
            .unwrap()
            .into_iter()
            .find(|contact| contact.peer == bob_peer)
            .unwrap()
            .name,
        fixture["duplicate_name"].as_str().unwrap()
    );
    alice.stop();
    bob.stop();
}

#[test]
fn desktop_screen_security_is_always_on_best_effort_with_rapid_lock() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../fixtures/b14-screen-security-parity.json"
    ))
    .unwrap();
    let policy = commands::screen_security_policy();
    assert!(policy.always_on);
    assert_eq!(
        policy.capture_prevention,
        fixture["platforms"]["desktop"]["capture_prevention"]
    );
    assert_eq!(
        policy.background_obscuring,
        fixture["platforms"]["desktop"]["background_obscuring"]
    );
    assert_eq!(policy.rapid_lock, "platform_enforced");
    assert!(!policy.limitations.is_empty());

    let config = include_str!("../tauri.conf.json");
    let frontend = include_str!("../../ui/main.js");
    assert!(config.contains(r#""contentProtected": true"#));
    assert!(frontend.contains("event.ctrlKey || event.metaKey"));
    assert!(frontend.contains("event.shiftKey"));
    assert!(frontend.contains("rapidLock()"));
    assert_eq!(fixture["desktop_shortcut"], "Ctrl/Cmd+Shift+L");
}

#[test]
fn desktop_incognito_keyboard_covers_every_editable_text_field_before_unlock() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../fixtures/b15-incognito-keyboard-parity.json"
    ))
    .unwrap();
    let policy = commands::incognito_keyboard_policy();
    assert!(policy.always_on);
    assert!(policy.applies_before_unlock);
    assert_eq!(
        policy.personalized_learning,
        fixture["platforms"]["desktop"]["personalized_learning"]
    );
    assert_eq!(
        policy.protected_fields,
        fixture["protected_fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    );
    assert!(policy
        .limitations
        .iter()
        .any(|text| text.contains("webview")));

    let html = include_str!("../../ui/index.html");
    let javascript = include_str!("../../ui/main.js");
    let editable_text_fields = html.matches("type=\"text\"").count()
        + html.matches("type=\"password\"").count()
        + html.matches("<textarea").count()
        - html
            .matches("<textarea class=\"share-hex\" rows=\"4\" readonly")
            .count();
    assert_eq!(26, editable_text_fields);
    assert_eq!(
        editable_text_fields,
        html.matches("data-incognito-input=").count()
    );
    assert!(html.contains("type=\"password\" id=\"gate-mnemonic\""));
    for attribute in [
        "autocomplete",
        "autocorrect",
        "autocapitalize",
        "spellcheck",
    ] {
        assert!(
            javascript.contains(&format!("setAttribute(\"{attribute}\", \"off\")"))
                || javascript.contains(&format!("setAttribute(\"{attribute}\", \"false\")"))
        );
    }
    assert!(javascript.contains("applyIncognitoInputPrivacy(body)"));
}

#[test]
fn private_theme_defaults_persists_restarts_and_emits_one_local_event() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../../fixtures/b12-theme-parity.json")).unwrap();
    assert_eq!(
        fixture["preferences"],
        serde_json::json!(["system", "light", "dark"])
    );
    let directory = tempfile::tempdir().unwrap();
    let events = Events::default();
    let session = open(directory.path(), "theme", &events);
    let queued = session.status().unwrap().queued;
    assert_eq!(
        session.theme().unwrap().preference,
        UiThemePreference::System
    );
    assert!(!session.theme().unwrap().persisted);
    assert!(session.set_theme(UiThemePreference::Dark).unwrap());
    assert!(!session.set_theme(UiThemePreference::Dark).unwrap());
    events.wait("theme changed", |event| {
        matches!(event, UiEvent::ThemeChanged)
    });
    assert_eq!(session.status().unwrap().queued, queued);
    session.stop();

    let reopened = open(directory.path(), "theme", &Events::default());
    assert_eq!(
        reopened.theme().unwrap().preference,
        UiThemePreference::Dark
    );
    assert!(reopened.theme().unwrap().persisted);
    reopened.stop();
}

#[test]
fn desktop_custom_icons_render_from_local_data_urls_and_survive_restart() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../fixtures/b13-custom-icon-parity.json"
    ))
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let events = Events::default();
    let session = open(directory.path(), "icons", &events);
    let queued = session.status().unwrap().queued;
    let note = UiCustomIconTarget {
        kind: "note_to_self".to_owned(),
        id: None,
    };
    assert!(session.custom_icon(note.clone()).unwrap().is_none());
    let note_icon = session
        .set_bundled_custom_icon(note.clone(), "compass".to_owned())
        .unwrap();
    assert_eq!(note_icon.media_type, "image/png");
    assert_eq!((note_icon.width, note_icon.height), (256, 256));
    assert!(note_icon.data_url.starts_with("data:image/png;base64,"));
    events.wait("custom icons changed", |event| {
        matches!(event, UiEvent::CustomIconsChanged)
    });

    let folder = session.create_folder("Icon target".to_owned()).unwrap();
    let folder_target = UiCustomIconTarget {
        kind: "folder".to_owned(),
        id: Some(folder.id),
    };
    let source = directory.path().join("desktop-icon.png");
    let pixels = image::ImageBuffer::from_fn(8, 6, |x, y| {
        image::Rgba([(x * 23) as u8, (y * 37) as u8, 120, 255])
    });
    image::DynamicImage::ImageRgba8(pixels)
        .save(&source)
        .unwrap();
    let folder_icon = session
        .set_custom_icon_from_path(
            folder_target.clone(),
            source.display().to_string(),
            Some(UiCustomIconCrop {
                x: 1,
                y: 0,
                width: 6,
                height: 6,
            }),
        )
        .unwrap();
    assert_ne!(folder_icon.data_url, note_icon.data_url);
    let usage = session.custom_icon_usage().unwrap();
    assert_eq!(usage.records, 2);
    assert_eq!(
        usage.bytes,
        note_icon.encoded_bytes + folder_icon.encoded_bytes
    );
    assert_eq!(session.status().unwrap().queued, queued);
    assert_eq!(
        fixture["network_behavior"]["transport_work"],
        serde_json::json!(0)
    );
    assert!(session.clear_custom_icon(folder_target.clone()).unwrap());
    assert!(!session.clear_custom_icon(folder_target.clone()).unwrap());
    assert!(session.custom_icon(folder_target).unwrap().is_none());
    session.stop();

    let reopened = open(directory.path(), "icons", &Events::default());
    assert_eq!(
        reopened.custom_icon(note).unwrap().unwrap().data_url,
        note_icon.data_url
    );
    reopened.stop();
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
    let formatted_source = "**hello** from the desktop ![pixel](https://invalid.test/p.png)";
    let msg_id = alice
        .send(bob_peer.clone(), formatted_source.to_owned())
        .unwrap();
    let got = b_ev.wait("bob's message event", |e| {
        matches!(e, UiEvent::MessageReceived { .. })
    });
    match got {
        UiEvent::MessageReceived { peer, body, .. } => {
            assert_eq!(peer, alice_peer);
            assert_eq!(body, formatted_source);
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
    assert_eq!(history[0].body, formatted_source);
    let inbox = bob.messages(alice_peer.clone()).unwrap();
    assert_eq!(inbox.len(), 1);
    assert!(!inbox[0].outbound);
    assert_eq!(inbox[0].state, "received");
    assert_eq!(inbox[0].body, formatted_source);

    std::thread::sleep(Duration::from_millis(300));
    let editable = alice
        .send(bob_peer.clone(), "desktop edit original".to_owned())
        .unwrap();
    b_ev.wait("bob's canonical desktop Text", |event| {
        matches!(
            event,
            UiEvent::MessageReceived {
                id,
                content_kind: "text",
                ..
            } if id == &editable
        )
    });
    a_ev.wait("editable desktop delivery", |event| {
        matches!(
            event,
            UiEvent::DeliveryUpdated { id, state: "delivered" } if id == &editable
        )
    });
    let edit = alice
        .edit_message(
            bob_peer.clone(),
            alice_peer.clone(),
            editable.clone(),
            "desktop edit revised".to_owned(),
        )
        .unwrap();
    b_ev.wait("desktop pairwise edit refresh", |event| {
        matches!(
            event,
            UiEvent::MessageEdited {
                peer,
                target_content_id,
            } if peer == &alice_peer && target_content_id == &editable
        )
    });
    a_ev.wait("desktop edit delivery", |event| {
        matches!(
            event,
            UiEvent::DeliveryUpdated { id, state: "delivered" } if id == &edit
        )
    });
    for history in [
        alice.messages(bob_peer.clone()).unwrap(),
        bob.messages(alice_peer.clone()).unwrap(),
    ] {
        assert_eq!(history.len(), 2, "edit events are not standalone bubbles");
        let message = history
            .iter()
            .find(|message| message.id == editable)
            .unwrap();
        assert_eq!(message.body, "desktop edit revised");
        assert!(message.edited);
        assert_eq!(message.edit_revision, 1);
        assert_eq!(message.versions.len(), 2);
    }

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
fn desktop_attachment_ux_pairwise_and_group_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let a_ev = Events::default();
    let b_ev = Events::default();
    let alice = open(dir.path(), "attachment-alice", &a_ev);
    let bob = open(dir.path(), "attachment-bob", &b_ev);

    let alice_addr = listen_addr(&alice);
    let bob_addr = listen_addr(&bob);
    let alice_bundle = alice.my_bundle().unwrap();
    let bob_bundle = bob.my_bundle().unwrap();
    let bob_peer = alice
        .add_contact("Bob".to_owned(), &bob_bundle.hex, &multiaddr_hint(bob_addr))
        .unwrap();
    let alice_peer = bob
        .add_contact(
            "Alice".to_owned(),
            &alice_bundle.hex,
            &multiaddr_hint(alice_addr),
        )
        .unwrap();

    // Attachment support is an authenticated session capability. Establish
    // the session first, exactly as the UI does through ordinary messaging.
    let hello = alice
        .send(bob_peer.clone(), "attachment setup".to_owned())
        .unwrap();
    b_ev.wait("attachment setup message", |event| {
        matches!(event, UiEvent::MessageReceived { body, .. } if body == "attachment setup")
    });
    a_ev.wait(
        "attachment setup delivered",
        |event| matches!(event, UiEvent::DeliveryUpdated { id, state: "delivered" } if *id == hello),
    );

    // The path chosen by the desktop dialog stays a path across the shell
    // boundary. The render model carries only honest object metadata and
    // verified-byte progress.
    let source = dir.path().join("desktop-source.png");
    image::RgbaImage::from_fn(24, 16, |x, y| {
        image::Rgba([(x * 9) as u8, (y * 13) as u8, 120, 255])
    })
    .save(&source)
    .unwrap();
    let original_bytes = std::fs::read(&source).unwrap();
    let direct = dir.path().join("desktop-edited-direct.png");
    let (ui_recipe, ffi_recipe) = image_recipe();
    edit_image(
        source.display().to_string(),
        direct.display().to_string(),
        ffi_recipe,
    )
    .unwrap();
    let review = alice
        .begin_image_edit(source.display().to_string())
        .unwrap();
    let review = alice.update_image_edit(review.token, ui_recipe).unwrap();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(review.data_url.split_once(',').unwrap().1)
        .unwrap();
    assert_eq!(bytes, std::fs::read(&direct).unwrap());
    assert_ne!(
        bytes, original_bytes,
        "the selected original must not be imported"
    );
    let carrier = alice
        .attachment_carrier_explanation("pairwise".to_owned(), bob_peer.clone())
        .unwrap();
    let content_id = alice
        .send_image_edit(
            review.token,
            "pairwise".to_owned(),
            bob_peer,
            Some("field-photo.png".to_owned()),
            carrier,
        )
        .unwrap();
    let outbound = alice.attachments().unwrap();
    assert_eq!(outbound.len(), 1);
    assert_eq!(outbound[0].content_id, content_id);
    assert_eq!(outbound[0].conversation, "pairwise");
    assert_eq!(outbound[0].direction, "outbound");
    assert_eq!(outbound[0].objects.len(), 1);
    assert_eq!(
        outbound[0].objects[0].filename.as_deref(),
        Some("field-photo.png")
    );
    assert_eq!(outbound[0].objects[0].total_bytes, bytes.len() as u64);
    assert_eq!(outbound[0].objects[0].media_type, "image/png");

    alice
        .pause_attachment(outbound[0].transfer_id.clone())
        .unwrap();
    assert_eq!(alice.attachments().unwrap()[0].state, "paused");
    alice
        .resume_attachment(outbound[0].transfer_id.clone())
        .unwrap();

    let offered = b_ev.wait("pairwise attachment offer", |event| {
        matches!(event, UiEvent::AttachmentUpdated { attachment }
            if attachment.content_id == content_id
                && attachment.direction == "inbound"
                && attachment.peer == alice_peer)
    });
    let inbound_transfer = match offered {
        UiEvent::AttachmentUpdated { attachment } => {
            assert_eq!(attachment.state, "awaiting_consent");
            assert_eq!(attachment.objects[0].verified_bytes, 0);
            attachment.transfer_id
        }
        other => panic!("wrong event: {other:?}"),
    };
    bob.accept_attachment(inbound_transfer.clone()).unwrap();
    b_ev.wait("pairwise attachment completion", |event| {
        matches!(event, UiEvent::AttachmentUpdated { attachment }
            if attachment.transfer_id == inbound_transfer && attachment.state == "complete")
    });
    let inbound = bob
        .attachments()
        .unwrap()
        .into_iter()
        .find(|attachment| attachment.transfer_id == inbound_transfer)
        .unwrap();
    assert_eq!(inbound.objects[0].verified_bytes, bytes.len() as u64);
    let protected_preview = bob.attachment_image(inbound_transfer.clone()).unwrap();
    assert!(protected_preview.starts_with("data:image/png;base64,"));
    let preview_bytes = base64::engine::general_purpose::STANDARD
        .decode(protected_preview.split_once(',').unwrap().1)
        .unwrap();
    assert_eq!(preview_bytes, bytes);

    // Export is caller-selected, exact, protected, and refuses overwrite.
    let exported = dir.path().join("desktop-export.bin");
    bob.export_attachment(inbound_transfer.clone(), exported.display().to_string())
        .unwrap();
    assert_eq!(std::fs::read(&exported).unwrap(), bytes);
    let err = bob
        .export_attachment(inbound_transfer.clone(), exported.display().to_string())
        .unwrap_err();
    assert!(err.contains("exist"), "got: {err}");
    assert_eq!(std::fs::read(&exported).unwrap(), bytes);

    bob.reject_attachment(inbound_transfer).unwrap();
    assert_eq!(bob.attachments().unwrap()[0].state, "rejected");
    a_ev.wait("sender observes attachment rejection", |event| {
        matches!(event, UiEvent::AttachmentUpdated { attachment }
            if attachment.transfer_id == outbound[0].transfer_id
                && attachment.state == "rejected")
    });
    alice
        .cancel_attachment(outbound[0].transfer_id.clone())
        .unwrap();
    assert_eq!(alice.attachments().unwrap()[0].state, "cancelled");
    let file_source = dir.path().join("desktop-generic.bin");
    let file_bytes = b"generic file exact bytes\0private";
    std::fs::write(&file_source, file_bytes).unwrap();
    let stale = alice
        .send_confirmed_attachment(
            "pairwise".to_owned(),
            outbound[0].peer.clone(),
            file_source.display().to_string(),
            "application/octet-stream".to_owned(),
            Some("field-notes.bin".to_owned()),
            "stale explanation".to_owned(),
        )
        .unwrap_err();
    assert!(stale.starts_with("carrier_changed:"));
    let file_carrier = alice
        .attachment_carrier_explanation("pairwise".to_owned(), outbound[0].peer.clone())
        .unwrap();
    assert!(file_carrier.contains("fresh realtime or bulk link"));
    let file_content = alice
        .send_confirmed_attachment(
            "pairwise".to_owned(),
            outbound[0].peer.clone(),
            file_source.display().to_string(),
            "application/octet-stream".to_owned(),
            Some("field-notes.bin".to_owned()),
            file_carrier,
        )
        .unwrap();
    let file_offer = b_ev.wait("generic file offer", |event| {
        matches!(event, UiEvent::AttachmentUpdated { attachment }
            if attachment.content_id == file_content && attachment.direction == "inbound")
    });
    let file_transfer = match file_offer {
        UiEvent::AttachmentUpdated { attachment } => attachment.transfer_id,
        other => panic!("wrong event: {other:?}"),
    };
    bob.accept_attachment(file_transfer.clone()).unwrap();
    b_ev.wait("generic file completion", |event| {
        matches!(event, UiEvent::AttachmentUpdated { attachment }
            if attachment.transfer_id == file_transfer && attachment.state == "complete")
    });
    let generic = bob
        .attachments()
        .unwrap()
        .into_iter()
        .find(|attachment| attachment.transfer_id == file_transfer)
        .unwrap();
    assert_eq!(generic.objects[0].presentation.kind, "other");
    assert_eq!(generic.objects[0].presentation.open_policy, "export_only");
    assert_eq!(
        generic.objects[0].presentation.warnings,
        vec!["unrecognized_type"]
    );
    let err = bob.open_attachment(file_transfer.clone()).unwrap_err();
    assert!(err.contains("export only"), "got: {err}");
    let file_export = dir.path().join("desktop-generic-received.bin");
    bob.export_attachment(file_transfer, file_export.display().to_string())
        .unwrap();
    assert_eq!(std::fs::read(file_export).unwrap(), file_bytes);

    let audio_bytes = canonical_audio(1_600);
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(native_audio_with_metadata(&audio_bytes));
    let audio_content = alice
        .send_recorded_audio(outbound[0].peer.clone(), encoded)
        .unwrap();
    let audio_offer = b_ev.wait("pairwise audio offer", |event| {
        matches!(event, UiEvent::AttachmentUpdated { attachment }
            if attachment.content_id == audio_content && attachment.direction == "inbound")
    });
    let audio_transfer = match audio_offer {
        UiEvent::AttachmentUpdated { attachment } => attachment.transfer_id,
        other => panic!("wrong event: {other:?}"),
    };
    bob.accept_attachment(audio_transfer.clone()).unwrap();
    b_ev.wait("pairwise audio completion", |event| {
        matches!(event, UiEvent::AttachmentUpdated { attachment }
            if attachment.transfer_id == audio_transfer && attachment.state == "complete")
    });
    let audio = bob.attachment_audio(audio_transfer).unwrap();
    assert_eq!(audio.duration_ms, 100);
    assert_eq!(audio.waveform.len(), 64);
    assert!(audio.data_url.starts_with("data:audio/wav;base64,"));
    let received = base64::engine::general_purpose::STANDARD
        .decode(audio.data_url.split_once(',').unwrap().1)
        .unwrap();
    assert_eq!(received, audio_bytes, "native metadata must be stripped");

    // The same thin shell methods cover an encrypt-once group offer and
    // consent/completion/export flow without adding group-specific protocol.
    let group = alice
        .create_group("Attachment crew".to_owned(), vec![outbound[0].peer.clone()])
        .unwrap();
    b_ev.wait(
        "group invite",
        |event| matches!(event, UiEvent::GroupUpdated { group: id } if *id == group),
    );
    let group_review = alice
        .begin_image_edit(source.display().to_string())
        .unwrap();
    let (group_recipe, _) = image_recipe();
    let group_review = alice
        .update_image_edit(group_review.token, group_recipe)
        .unwrap();
    let group_carrier = alice
        .attachment_carrier_explanation("group".to_owned(), group.clone())
        .unwrap();
    let group_content_id = alice
        .send_image_edit(
            group_review.token,
            "group".to_owned(),
            group.clone(),
            Some("edited-image.png".to_owned()),
            group_carrier,
        )
        .unwrap();
    let group_offer = b_ev.wait("group attachment offer", |event| {
        matches!(event, UiEvent::AttachmentUpdated { attachment }
            if attachment.content_id == group_content_id
                && attachment.conversation == "group"
                && attachment.group.as_deref() == Some(group.as_str()))
    });
    let group_transfer = match group_offer {
        UiEvent::AttachmentUpdated { attachment } => attachment.transfer_id,
        other => panic!("wrong event: {other:?}"),
    };
    bob.accept_attachment(group_transfer.clone()).unwrap();
    b_ev.wait("group attachment completion", |event| {
        matches!(event, UiEvent::AttachmentUpdated { attachment }
            if attachment.transfer_id == group_transfer && attachment.state == "complete")
    });
    let group_image = bob.attachment_image(group_transfer).unwrap();
    let group_bytes = base64::engine::general_purpose::STANDARD
        .decode(group_image.split_once(',').unwrap().1)
        .unwrap();
    assert_eq!(group_bytes, bytes);

    alice.stop();
    bob.stop();
}

#[test]
fn desktop_group_mentions_preserve_exact_utf8_spans_and_notify_only_the_target() {
    let dir = tempfile::tempdir().unwrap();
    let a_ev = Events::default();
    let b_ev = Events::default();
    let alice = open(dir.path(), "mention-alice", &a_ev);
    let bob = open(dir.path(), "mention-bob", &b_ev);

    let alice_addr = listen_addr(&alice);
    let bob_addr = listen_addr(&bob);
    let alice_bundle = alice.my_bundle().unwrap();
    let bob_bundle = bob.my_bundle().unwrap();
    let bob_peer = alice
        .add_contact(
            "Same name".to_owned(),
            &bob_bundle.hex,
            &multiaddr_hint(bob_addr),
        )
        .unwrap();
    let alice_at_bob = bob
        .add_contact(
            "Same name".to_owned(),
            &alice_bundle.hex,
            &multiaddr_hint(alice_addr),
        )
        .unwrap();
    let group = alice
        .create_group("Unicode crew".to_owned(), vec![bob_peer.clone()])
        .unwrap();
    b_ev.wait(
        "mention group invite",
        |event| matches!(event, UiEvent::GroupUpdated { group: updated } if updated == &group),
    );

    let handshake = alice
        .send(bob_peer.clone(), "mention capability handshake".to_owned())
        .unwrap();
    b_ev.wait("mention capability handshake", |event| {
        matches!(event, UiEvent::MessageReceived { peer, body, .. }
            if peer == &alice_at_bob && body == "mention capability handshake")
    });
    a_ev.wait("mention capability receipt", |event| {
        matches!(event, UiEvent::DeliveryUpdated { id, state: "delivered" }
            if id == &handshake)
    });

    let deadline = Instant::now() + Duration::from_secs(5);
    let capability = loop {
        let capability = alice.group_mention_capability(group.clone()).unwrap();
        if capability.supported {
            break capability;
        }
        assert!(
            Instant::now() < deadline,
            "mention capability did not become supported: {:?}",
            capability.issues
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(capability.issues.is_empty());

    let text = "Meet 👩🏽‍🚀 @Same name by e\u{301}ast";
    let visible = "@Same name";
    let start = text.find(visible).unwrap() as u32;
    let end = start + visible.len() as u32;
    let expected_spans = vec![UiMentionSpan {
        start,
        end,
        target: bob_peer.clone(),
    }];
    let mention_id = alice
        .send_group_mention(
            group.clone(),
            text.to_owned(),
            expected_spans.clone(),
            capability.review_token,
        )
        .unwrap();
    let received = b_ev.wait("semantic mention", |event| {
        matches!(event, UiEvent::GroupMessageReceived {
            group: received_group,
            id,
            body,
            content_kind: "mention",
            mention_spans,
            ..
        } if received_group == &group && id == &mention_id && body == text
            && mention_spans == &expected_spans)
    });
    b_ev.wait("local mention signal", |event| {
        matches!(
            (event, &received),
            (
                UiEvent::MentionReceived { id },
                UiEvent::GroupMessageReceived { id: received_id, .. }
            ) if id == received_id
        )
    });
    let stored = bob
        .group_messages(group.clone())
        .unwrap()
        .into_iter()
        .find(|message| message.id == mention_id)
        .unwrap();
    assert_eq!(stored.body, text);
    assert_eq!(stored.content_kind, "mention");
    assert_eq!(stored.mention_spans, expected_spans);

    let plain_id = alice.send_group(group.clone(), text.to_owned()).unwrap();
    b_ev.wait("plain fallback", |event| {
        matches!(event, UiEvent::GroupMessageReceived {
            id,
            body,
            content_kind: "text",
            mention_spans,
            ..
        } if id == &plain_id && body == text && mention_spans.is_empty())
    });
    a_ev.wait("plain fallback receipt", |event| {
        matches!(event, UiEvent::GroupDeliveryUpdated {
            id,
            peer,
            state: "delivered",
        } if id == &plain_id && peer == &bob_peer)
    });
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        b_ev.count(|event| matches!(event, UiEvent::MentionReceived { .. })),
        1
    );

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

    std::thread::sleep(Duration::from_millis(300));
    let editable = alice
        .send_group(group.clone(), "desktop group edit original".to_owned())
        .unwrap();
    b_ev.wait("Bob's editable group Text", |event| {
        matches!(
            event,
            UiEvent::GroupMessageReceived {
                id,
                content_kind: "text",
                ..
            } if id == &editable
        )
    });
    a_ev.wait("editable group copy delivered", |event| {
        matches!(
            event,
            UiEvent::GroupDeliveryUpdated { id, peer, state: "delivered" }
                if id == &editable && peer == &bob_peer
        )
    });
    let edit = alice
        .edit_group_message(
            group.clone(),
            alice_at_bob.clone(),
            editable.clone(),
            "desktop group edit revised".to_owned(),
        )
        .unwrap();
    b_ev.wait("desktop group edit refresh", |event| {
        matches!(
            event,
            UiEvent::GroupMessageEdited {
                group: event_group,
                sender,
                target_content_id,
            } if event_group == &group && sender == &alice_at_bob
                && target_content_id == &editable
        )
    });
    a_ev.wait("desktop group edit delivery", |event| {
        matches!(
            event,
            UiEvent::GroupDeliveryUpdated { id, peer, state: "delivered" }
                if id == &edit && peer == &bob_peer
        )
    });
    for history in [
        alice.group_messages(group.clone()).unwrap(),
        bob.group_messages(group.clone()).unwrap(),
    ] {
        let message = history
            .iter()
            .find(|message| message.id == editable)
            .unwrap();
        assert_eq!(message.body, "desktop group edit revised");
        assert!(message.edited);
        assert_eq!(message.edit_revision, 1);
        assert_eq!(message.versions.len(), 2);
    }
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

#[test]
fn desktop_private_label_manager_assignment_filters_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let events = Events::default();
    let bob_events = Events::default();
    let alice = open(dir.path(), "alice-labels", &events);
    let bob = open(dir.path(), "bob-labels", &bob_events);
    let bob_peer = alice
        .add_contact(
            "Same visible target".to_owned(),
            &bob.my_bundle().unwrap().hex,
            &multiaddr_hint(listen_addr(&bob)),
        )
        .unwrap();
    let group = alice
        .create_group("Same visible target".to_owned(), vec![bob_peer.clone()])
        .unwrap();
    let peer = UiLabelTarget {
        kind: "peer".to_owned(),
        id: Some(bob_peer),
    };
    let group_target = UiLabelTarget {
        kind: "group".to_owned(),
        id: Some(group),
    };
    let note = UiLabelTarget {
        kind: "note_to_self".to_owned(),
        id: None,
    };
    let queued_before = alice.status().unwrap().queued;

    let first = alice
        .create_label("\u{2067}e\u{301} 🧭\u{2069}".to_owned(), "blue".to_owned())
        .unwrap();
    let duplicate = alice
        .create_label("\u{2067}e\u{301} 🧭\u{2069}".to_owned(), "pink".to_owned())
        .unwrap();
    assert_ne!(first.id, duplicate.id);
    assert_eq!((first.order, duplicate.order), (0, 1));
    assert!(alice.assign_label(first.id.clone(), peer.clone()).unwrap());
    assert!(!alice.assign_label(first.id.clone(), peer.clone()).unwrap());
    assert!(alice
        .assign_label(first.id.clone(), group_target.clone())
        .unwrap());
    assert!(alice
        .assign_label(duplicate.id.clone(), peer.clone())
        .unwrap());
    assert!(alice
        .assign_label(duplicate.id.clone(), note.clone())
        .unwrap());

    let any = alice
        .filter_labels(
            vec![first.id.clone(), duplicate.id.clone()],
            "any".to_owned(),
        )
        .unwrap();
    assert_eq!(any.conversations.len(), 3);
    let all = alice
        .filter_labels(
            vec![duplicate.id.clone(), first.id.clone(), first.id.clone()],
            "all".to_owned(),
        )
        .unwrap();
    assert_eq!(all.selected, vec![duplicate.id.clone(), first.id.clone()]);
    assert_eq!(
        all.conversations,
        vec![komms_desktop::session::UiLabelConversation {
            target: peer.clone(),
            display_name: Some("Same visible target".to_owned()),
        }]
    );

    let renamed = alice
        .update_label(
            first.id.clone(),
            " exact\tname ".to_owned(),
            "teal".to_owned(),
        )
        .unwrap();
    assert_eq!((renamed.id, renamed.order), (first.id.clone(), 0));
    assert_eq!(alice.label_membership(first.id.clone()).unwrap().len(), 2);
    assert!(alice.delete_label(first.id.clone(), false).is_err());
    assert_eq!(
        alice
            .label_delete_assignment_count(first.id.clone())
            .unwrap(),
        2
    );
    assert_eq!(alice.delete_label(first.id, true).unwrap(), 2);
    assert_eq!(alice.status().unwrap().queued, queued_before);
    events.wait("local label change", |event| {
        matches!(event, UiEvent::LabelsChanged)
    });
    assert!(events.count(|event| matches!(event, UiEvent::LabelsChanged)) >= 1);

    alice.stop();
    let alice = open(dir.path(), "alice-labels", &Events::default());
    let restored = alice.labels().unwrap();
    assert_eq!(
        (&restored[0].id, &restored[0].name, &restored[0].color),
        (&duplicate.id, &duplicate.name, &duplicate.color)
    );
    assert_eq!(restored[0].order, 0);
    assert_eq!(alice.labels_for_conversation(note).unwrap(), restored);
    assert!(alice.stale_labels().unwrap().is_empty());
    alice.stop();
    bob.stop();
}

#[test]
fn desktop_private_folder_manager_navigation_composition_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let events = Events::default();
    let bob_events = Events::default();
    let alice = open(dir.path(), "alice-folders", &events);
    let bob = open(dir.path(), "bob-folders", &bob_events);
    let bob_peer = alice
        .add_contact(
            "Same visible target".to_owned(),
            &bob.my_bundle().unwrap().hex,
            &multiaddr_hint(listen_addr(&bob)),
        )
        .unwrap();
    let group = alice
        .create_group("Same visible target".to_owned(), vec![bob_peer.clone()])
        .unwrap();
    let peer = UiFolderTarget {
        kind: "peer".to_owned(),
        id: Some(bob_peer.clone()),
    };
    let group_target = UiFolderTarget {
        kind: "group".to_owned(),
        id: Some(group.clone()),
    };
    let note = UiFolderTarget {
        kind: "note_to_self".to_owned(),
        id: None,
    };
    let queued_before = alice.status().unwrap().queued;

    let first = alice
        .create_folder("\u{2067}e\u{301} 🧭\u{2069}".to_owned())
        .unwrap();
    let second = alice
        .create_folder("\u{2067}e\u{301} 🧭\u{2069}".to_owned())
        .unwrap();
    assert_ne!(first.id, second.id);
    assert_eq!((first.order, second.order), (0, 1));
    assert_eq!(
        alice
            .reorder_folders(vec![second.id.clone(), first.id.clone()])
            .unwrap()
            .iter()
            .map(|folder| folder.id.clone())
            .collect::<Vec<_>>(),
        vec![second.id.clone(), first.id.clone()]
    );
    assert!(alice
        .move_to_folder(first.id.clone(), peer.clone())
        .unwrap());
    assert!(alice
        .move_to_folder(first.id.clone(), group_target.clone())
        .unwrap());
    assert!(alice
        .move_to_folder(second.id.clone(), note.clone())
        .unwrap());
    assert!(!alice
        .move_to_folder(second.id.clone(), note.clone())
        .unwrap());

    let label = alice
        .create_label("folder composition".to_owned(), "teal".to_owned())
        .unwrap();
    alice
        .assign_label(
            label.id.clone(),
            UiLabelTarget {
                kind: "peer".to_owned(),
                id: Some(bob_peer.clone()),
            },
        )
        .unwrap();
    alice
        .assign_label(
            label.id.clone(),
            UiLabelTarget {
                kind: "group".to_owned(),
                id: Some(group.clone()),
            },
        )
        .unwrap();
    let composed = alice
        .folder_conversations(
            UiFolderSelection {
                kind: "folder".to_owned(),
                id: Some(first.id.clone()),
            },
            vec![label.id.clone()],
            "any".to_owned(),
        )
        .unwrap();
    assert_eq!(composed.conversations.len(), 2);
    let peer_pin = UiPinTarget {
        kind: "peer".to_owned(),
        id: Some(bob_peer),
    };
    let group_pin = UiPinTarget {
        kind: "group".to_owned(),
        id: Some(group),
    };
    assert!(alice.pin_conversation(peer_pin.clone()).unwrap());
    assert!(alice.pin_conversation(group_pin.clone()).unwrap());
    assert!(!alice.pin_conversation(peer_pin.clone()).unwrap());
    alice
        .reorder_pins(vec![group_pin.clone(), peer_pin.clone()])
        .unwrap();
    let pinned = alice
        .pin_conversations(
            UiFolderSelection {
                kind: "folder".to_owned(),
                id: Some(first.id.clone()),
            },
            vec![label.id.clone()],
            "any".to_owned(),
        )
        .unwrap();
    assert_eq!(
        pinned
            .conversations
            .iter()
            .map(|row| (row.target.kind.as_str(), row.pinned))
            .collect::<Vec<_>>(),
        vec![("group", true), ("peer", true)]
    );
    assert!(alice.cleanup_stale_pin(group_pin.clone()).is_err());
    events.wait("local pin change", |event| {
        matches!(event, UiEvent::PinsChanged)
    });
    assert!(alice.unfile_conversation(peer.clone()).unwrap());
    assert!(!alice.unfile_conversation(peer).unwrap());
    assert_eq!(
        alice
            .folder_delete_assignment_count(first.id.clone())
            .unwrap(),
        1
    );
    assert!(alice.delete_folder(first.id.clone(), false).is_err());
    assert_eq!(alice.status().unwrap().queued, queued_before);
    events.wait("local folder change", |event| {
        matches!(event, UiEvent::FoldersChanged)
    });

    alice.stop();
    let alice = open(dir.path(), "alice-folders", &Events::default());
    assert_eq!(
        alice
            .folders()
            .unwrap()
            .iter()
            .map(|folder| folder.id.clone())
            .collect::<Vec<_>>(),
        vec![second.id.clone(), first.id.clone()]
    );
    assert_eq!(
        alice.conversation_folder(note).unwrap().unwrap().id,
        second.id
    );
    assert_eq!(alice.folder_membership(first.id.clone()).unwrap().len(), 1);
    assert_eq!(
        alice
            .pins()
            .unwrap()
            .iter()
            .map(|pin| pin.target.clone())
            .collect::<Vec<_>>(),
        vec![group_pin, peer_pin]
    );
    assert_eq!(alice.delete_folder(first.id.clone(), true).unwrap(), 1);
    let replacement = alice.create_folder(first.name).unwrap();
    assert_ne!(replacement.id, first.id);
    assert!(alice.folder_membership(replacement.id).unwrap().is_empty());
    assert!(alice.stale_folders().unwrap().is_empty());
    alice.stop();
    bob.stop();
}
