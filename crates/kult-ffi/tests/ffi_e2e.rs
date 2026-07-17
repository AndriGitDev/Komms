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
    attachment_file_presentation, default_config, edit_image, incognito_keyboard_policy,
    probe_edited_image, probe_recorded_audio, screen_security_policy, AttachmentDirection,
    AttachmentFileKind, AttachmentFileWarning, AttachmentOpenPolicy, AttachmentState,
    CarrierCapability, Config, ContactNameWarning, ContentKind, CustomIconCrop, CustomIconTarget,
    CustomIconTargetKind, DeliveryState, DeviceLinkSelection, Event, EventListener, FfiError,
    FolderErrorCode, FolderSelection, FolderSelectionKind, FolderTarget, FolderTargetKind,
    GroupRole, Hint, ImageCrop, ImageEditRecipe, ImageEditRegion, ImageEditRegionKind,
    IncognitoKeyboardLevel, IncognitoKeyboardPlatform, KdfChoice, KultNode, LabelErrorCode,
    LabelMatchMode, LabelTarget, LabelTargetKind, MentionSpan, PinErrorCode, PinTarget,
    PinTargetKind, ScheduledConversation, ScreenSecurityLevel, ScreenSecurityPlatform,
    TextFormatBlockKind, TextFormatHighlight, ThemePreference,
};

fn file_presentation_parity_fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/c1-file-presentation-parity.json"
    ))
    .expect("valid shared C1 file-presentation fixture")
}

fn ephemeral_parity_fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../fixtures/c4-ephemeral-parity.json"))
        .expect("valid shared C4 ephemeral fixture")
}

fn label_parity_fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../fixtures/b18-label-parity.json"))
        .expect("valid shared B18 label fixture")
}

fn folder_parity_fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../fixtures/b10-folder-parity.json"))
        .expect("valid shared B10 folder fixture")
}

fn pin_parity_fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../fixtures/b11-pin-parity.json"))
        .expect("valid shared B11 pin fixture")
}

fn theme_parity_fixture() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../fixtures/b12-theme-parity.json"))
        .expect("valid shared B12 theme fixture")
}

fn custom_icon_parity_fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/b13-custom-icon-parity.json"
    ))
    .expect("valid shared B13 custom-icon fixture")
}

fn screen_security_parity_fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/b14-screen-security-parity.json"
    ))
    .expect("valid shared B14 screen-security fixture")
}

fn incognito_keyboard_parity_fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/b15-incognito-keyboard-parity.json"
    ))
    .expect("valid shared B15 incognito-keyboard fixture")
}

fn contact_rename_parity_fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/b5-contact-rename-parity.json"
    ))
    .expect("valid shared B5 contact-rename fixture")
}

fn text_formatting_parity_fixture() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../fixtures/b9-text-formatting-parity.json"
    ))
    .expect("valid shared B9 text-formatting fixture")
}

#[test]
fn file_presentation_via_ffi_matches_shared_fail_closed_policy() {
    let fixture = file_presentation_parity_fixture();
    for case in fixture["cases"].as_array().unwrap() {
        let result = attachment_file_presentation(
            case["media_type"].as_str().unwrap().to_owned(),
            case["filename"].as_str().map(ToOwned::to_owned),
        );
        let kind = match result.kind {
            AttachmentFileKind::Image => "image",
            AttachmentFileKind::Audio => "audio",
            AttachmentFileKind::Video => "video",
            AttachmentFileKind::Document => "document",
            AttachmentFileKind::Archive => "archive",
            AttachmentFileKind::Executable => "executable",
            AttachmentFileKind::Other => "other",
        };
        let policy = match result.open_policy {
            AttachmentOpenPolicy::ProtectedMedia => "protected_media",
            AttachmentOpenPolicy::ExternalOpen => "external_open",
            AttachmentOpenPolicy::ExportOnly => "export_only",
        };
        let warnings = result
            .warnings
            .into_iter()
            .map(|warning| match warning {
                AttachmentFileWarning::MediaTypeMismatch => "media_type_mismatch",
                AttachmentFileWarning::DangerousType => "dangerous_type",
                AttachmentFileWarning::UnrecognizedType => "unrecognized_type",
                AttachmentFileWarning::MissingFilename => "missing_filename",
            })
            .collect::<Vec<_>>();
        assert_eq!(kind, case["kind"].as_str().unwrap());
        assert_eq!(policy, case["open_policy"].as_str().unwrap());
        assert_eq!(
            warnings,
            case["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn safe_text_formatting_via_ffi_matches_shared_corpus_without_delivery_work() {
    let fixture = text_formatting_parity_fixture();
    let directory = tempfile::tempdir().unwrap();
    let node = KultNode::start(
        test_config(directory.path(), "text-formatting"),
        Box::new(Recorder::default()),
    )
    .unwrap();
    let queued = node.status().unwrap().queued;
    for case in fixture["cases"].as_array().unwrap() {
        let highlights = case["highlights"]
            .as_array()
            .unwrap()
            .iter()
            .map(|highlight| TextFormatHighlight {
                start: highlight["start"].as_u64().unwrap() as u32,
                end: highlight["end"].as_u64().unwrap() as u32,
            })
            .collect();
        let formatted = node
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
                .map(|block| match block.kind {
                    TextFormatBlockKind::Paragraph => "paragraph",
                    TextFormatBlockKind::Quote => "quote",
                    TextFormatBlockKind::UnorderedListItem => "unordered_list_item",
                    TextFormatBlockKind::OrderedListItem => "ordered_list_item",
                    TextFormatBlockKind::CodeBlock => "code_block",
                })
                .collect::<Vec<_>>(),
            case["block_kinds"]
                .as_array()
                .unwrap()
                .iter()
                .map(|kind| kind.as_str().unwrap())
                .collect::<Vec<_>>()
        );
    }
    assert_eq!(node.status().unwrap().queued, queued);
    node.stop();
}

#[test]
fn contact_rename_is_normalized_warned_private_and_duplicate_capable_via_ffi() {
    let fixture = contact_rename_parity_fixture();
    let directory = tempfile::tempdir().unwrap();
    let events = Recorder::default();
    let alice = KultNode::start(
        test_config(directory.path(), "contact-rename-alice"),
        Box::new(events.clone()),
    )
    .unwrap();
    let bob = KultNode::start(
        test_config(directory.path(), "contact-rename-bob"),
        Box::new(Recorder::default()),
    )
    .unwrap();
    let carol = KultNode::start(
        test_config(directory.path(), "contact-rename-carol"),
        Box::new(Recorder::default()),
    )
    .unwrap();
    let bob_peer = alice
        .add_contact("Bob".to_owned(), bob.handshake_bundle().unwrap(), vec![])
        .unwrap();
    let carol_peer = alice
        .add_contact(
            fixture["duplicate_name"].as_str().unwrap().to_owned(),
            carol.handshake_bundle().unwrap(),
            vec![],
        )
        .unwrap();
    assert_ne!(bob_peer, carol_peer);
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
    assert_eq!(duplicate.warnings, vec![ContactNameWarning::DuplicateName]);
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
            .filter(|contact| { contact.name == fixture["duplicate_name"].as_str().unwrap() })
            .count(),
        2
    );
    assert_eq!(alice.status().unwrap().queued, queued_before);
    events.wait("contact renamed", |event| {
        matches!(event, Event::ContactRenamed { peer, name }
            if peer == &bob_peer && name == fixture["duplicate_name"].as_str().unwrap())
    });
    alice.stop();
    bob.stop();
    carol.stop();
}

#[test]
fn incognito_keyboard_policy_is_available_before_unlock_with_exact_platform_parity() {
    let fixture = incognito_keyboard_parity_fixture();
    let cases = [
        (IncognitoKeyboardPlatform::Android, "android"),
        (IncognitoKeyboardPlatform::Ios, "ios"),
        (IncognitoKeyboardPlatform::Desktop, "desktop"),
    ];
    for (platform, token) in cases {
        let policy = incognito_keyboard_policy(platform);
        let expected = &fixture["platforms"][token];
        let level = |value| match value {
            IncognitoKeyboardLevel::PlatformEnforced => "platform_enforced",
            IncognitoKeyboardLevel::PlatformRequested => "platform_requested",
            IncognitoKeyboardLevel::BestEffort => "best_effort",
            IncognitoKeyboardLevel::Unavailable => "unavailable",
        };
        assert!(policy.always_on);
        assert!(policy.applies_before_unlock);
        assert_eq!(
            level(policy.personalized_learning),
            expected["personalized_learning"]
        );
        assert_eq!(level(policy.suggestions), expected["suggestions"]);
        assert_eq!(level(policy.spellcheck), expected["spellcheck"]);
        assert_eq!(
            level(policy.secret_text_masking),
            expected["secret_text_masking"]
        );
        assert_eq!(
            policy.protected_fields,
            ["message", "search", "passphrase", "mnemonic", "name"]
        );
        assert!(!policy.mechanism.is_empty());
        assert!(!policy.limitations.is_empty());
    }
}

#[test]
fn screen_security_policy_is_available_before_unlock_with_exact_platform_parity() {
    let fixture = screen_security_parity_fixture();
    let cases = [
        (ScreenSecurityPlatform::Android, "android"),
        (ScreenSecurityPlatform::Ios, "ios"),
        (ScreenSecurityPlatform::Desktop, "desktop"),
    ];
    for (platform, token) in cases {
        let policy = screen_security_policy(platform);
        let expected = &fixture["platforms"][token];
        let level = |value| match value {
            ScreenSecurityLevel::PlatformEnforced => "platform_enforced",
            ScreenSecurityLevel::BestEffort => "best_effort",
            ScreenSecurityLevel::Unavailable => "unavailable",
        };
        assert!(policy.always_on);
        assert_eq!(
            level(policy.capture_prevention),
            expected["capture_prevention"]
        );
        assert_eq!(
            level(policy.background_obscuring),
            expected["background_obscuring"]
        );
        assert_eq!(
            level(policy.capture_detection),
            expected["capture_detection"]
        );
        assert_eq!(level(policy.rapid_lock), expected["rapid_lock"]);
        assert!(!policy.mechanism.is_empty());
        assert!(!policy.limitations.is_empty());
    }
}

#[test]
fn private_theme_via_ffi_defaults_is_idempotent_and_emits_local_event() {
    let fixture = theme_parity_fixture();
    assert_eq!(fixture["preference_key"], "appearance.theme");
    assert_eq!(
        fixture["preferences"],
        serde_json::json!(["system", "light", "dark"])
    );
    let directory = tempfile::tempdir().unwrap();
    let recorder = Recorder::default();
    let node = KultNode::start(
        test_config(directory.path(), "theme"),
        Box::new(recorder.clone()),
    )
    .expect("node starts");
    let queued = node.status().unwrap().queued;
    let initial = node.theme().unwrap();
    assert_eq!(initial.preference, ThemePreference::System);
    assert!(!initial.persisted);
    assert!(node.set_theme(ThemePreference::Dark).unwrap());
    assert!(!node.set_theme(ThemePreference::Dark).unwrap());
    recorder.wait("theme event", |event| matches!(event, Event::ThemeChanged));
    assert_eq!(node.theme().unwrap().preference, ThemePreference::Dark);
    assert_eq!(node.status().unwrap().queued, queued);
    node.stop();

    let reopened = KultNode::start(
        test_config(directory.path(), "theme"),
        Box::new(Recorder::default()),
    )
    .unwrap();
    assert_eq!(reopened.theme().unwrap().preference, ThemePreference::Dark);
    assert!(reopened.theme().unwrap().persisted);
    reopened.stop();
}

#[test]
fn private_custom_icons_via_ffi_have_canonical_parity_and_safe_fallback() {
    let fixture = custom_icon_parity_fixture();
    let directory = tempfile::tempdir().unwrap();
    let recorder = Recorder::default();
    let node = KultNode::start(
        test_config(directory.path(), "icons"),
        Box::new(recorder.clone()),
    )
    .expect("node starts");
    let queued = node.status().unwrap().queued;
    let note = CustomIconTarget {
        kind: CustomIconTargetKind::NoteToSelf,
        id: None,
    };
    assert!(node.custom_icon(note.clone()).unwrap().is_none());

    let glyph = fixture["bundled_glyphs"][7].as_str().unwrap();
    let icon = node
        .set_bundled_custom_icon(note.clone(), glyph.to_owned())
        .unwrap();
    assert_eq!(icon.target, note);
    assert_eq!(icon.media_type, fixture["canonical_output"]["media_type"]);
    assert_eq!(icon.width, fixture["canonical_output"]["width"]);
    assert_eq!(icon.height, fixture["canonical_output"]["height"]);
    assert!(icon.bytes.starts_with(b"\x89PNG\r\n\x1a\n"));
    recorder.wait("custom icon event", |event| {
        matches!(event, Event::CustomIconsChanged)
    });

    let folder = node.create_folder("Icon target".to_owned()).unwrap();
    let folder_target = CustomIconTarget {
        kind: CustomIconTargetKind::Folder,
        id: Some(folder.id),
    };
    let source = directory.path().join("icon-source.png");
    let pixels = image::ImageBuffer::from_fn(6, 4, |x, y| {
        image::Rgba([(x * 31) as u8, (y * 47) as u8, 90, 255])
    });
    image::DynamicImage::ImageRgba8(pixels)
        .save(&source)
        .unwrap();
    let folder_icon = node
        .set_custom_icon_from_path(
            folder_target.clone(),
            source.display().to_string(),
            Some(CustomIconCrop {
                x: 1,
                y: 0,
                width: 4,
                height: 4,
            }),
        )
        .unwrap();
    assert_eq!(folder_icon.target, folder_target);
    assert_ne!(folder_icon.bytes, icon.bytes);

    let usage = node.custom_icon_quota_usage().unwrap();
    assert_eq!(usage.records, 2);
    assert_eq!(
        usage.bytes,
        (icon.bytes.len() + folder_icon.bytes.len()) as u64
    );
    assert_eq!(node.status().unwrap().queued, queued);
    assert!(node.clear_custom_icon(folder_target.clone()).unwrap());
    assert!(!node.clear_custom_icon(folder_target.clone()).unwrap());
    assert!(node.custom_icon(folder_target).unwrap().is_none());
    assert!(node
        .set_bundled_custom_icon(note.clone(), "not-a-glyph".to_owned())
        .is_err());
    assert!(node
        .custom_icon(CustomIconTarget {
            kind: CustomIconTargetKind::NoteToSelf,
            id: Some("unexpected".to_owned()),
        })
        .is_err());
    node.stop();

    let reopened = KultNode::start(
        test_config(directory.path(), "icons"),
        Box::new(Recorder::default()),
    )
    .unwrap();
    assert_eq!(
        reopened.custom_icon(note).unwrap().unwrap().bytes,
        icon.bytes
    );
    reopened.stop();
}

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
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {what}; events: {:#?}",
                self.events.lock().unwrap()
            );
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

fn mention_capability(node: &KultNode, group: &str) -> kult_ffi::GroupMentionCapability {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let capability = node
            .group_mention_capability(group.to_owned())
            .expect("mention capability");
        if capability.supported {
            return capability;
        }
        assert!(
            Instant::now() < deadline,
            "mention capability intersection stayed unsupported: {:?}",
            capability.issues
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn poll_revision(
    node: &KultNode,
    group: &str,
    poll_id: &str,
    revision: u64,
) -> kult_ffi::GroupPoll {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(poll) = node
            .group_polls(group.to_owned())
            .expect("group polls")
            .into_iter()
            .find(|poll| {
                poll.id == poll_id && poll.votes.iter().any(|vote| vote.revision == revision)
            })
        {
            return poll;
        }
        assert!(Instant::now() < deadline, "poll revision did not converge");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn closed_poll(node: &KultNode, group: &str, poll_id: &str) -> kult_ffi::GroupPoll {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(poll) = node
            .group_polls(group.to_owned())
            .expect("group polls")
            .into_iter()
            .find(|poll| poll.id == poll_id && poll.closed)
        {
            return poll;
        }
        assert!(Instant::now() < deadline, "poll closure did not converge");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn authority_generation(node: &KultNode, group: &str, generation: u64) -> kult_ffi::GroupAuthority {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let authority = node
            .group_authority(group.to_owned())
            .expect("group authority");
        if authority.signed && authority.generation >= generation {
            return authority;
        }
        assert!(
            Instant::now() < deadline,
            "authority generation did not converge"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_group_presence(node: &KultNode, group: &str, present: bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let found = node
            .groups()
            .expect("groups")
            .iter()
            .any(|candidate| candidate.id == group);
        if found == present {
            return;
        }
        assert!(Instant::now() < deadline, "group presence did not converge");
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
fn private_labels_via_ffi_have_typed_parity_and_zero_delivery_work() {
    let fixture = label_parity_fixture();
    let duplicate_name = fixture["duplicate_name"].as_str().unwrap();
    let colors = fixture["create_colors"].as_array().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let recorder = Recorder::default();
    let node = KultNode::start(
        test_config(directory.path(), "labels"),
        Box::new(recorder.clone()),
    )
    .expect("node starts");
    let queued_before = node.status().unwrap().queued;
    let own_peer = node
        .add_contact(
            "\u{2067}duplicate\u{2069}".to_owned(),
            node.handshake_bundle().unwrap(),
            vec![],
        )
        .unwrap();
    let group = node
        .create_group("e\u{301} group".to_owned(), vec![])
        .unwrap();

    let first = node
        .create_label(
            duplicate_name.to_owned(),
            colors[0].as_str().unwrap().to_owned(),
        )
        .unwrap();
    let second = node
        .create_label(
            duplicate_name.to_owned(),
            colors[1].as_str().unwrap().to_owned(),
        )
        .unwrap();
    assert_ne!(first.id, second.id);
    assert_eq!(
        vec![first.order, second.order],
        fixture["expected_orders"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_u64().unwrap() as u32)
            .collect::<Vec<_>>()
    );
    recorder.wait("label event", |event| matches!(event, Event::LabelsChanged));

    let peer_target = LabelTarget {
        kind: LabelTargetKind::Peer,
        id: Some(own_peer.clone()),
    };
    let group_target = LabelTarget {
        kind: LabelTargetKind::Group,
        id: Some(group.clone()),
    };
    let note_target = LabelTarget {
        kind: LabelTargetKind::NoteToSelf,
        id: None,
    };
    for target in [
        peer_target.clone(),
        group_target.clone(),
        note_target.clone(),
    ] {
        assert!(node.assign_label(first.id.clone(), target).unwrap());
    }
    for target in [group_target.clone(), note_target.clone()] {
        assert!(node.assign_label(second.id.clone(), target).unwrap());
    }
    assert!(!node
        .assign_label(second.id.clone(), note_target.clone())
        .unwrap());

    let membership = node.label_membership(first.id.clone()).unwrap();
    assert_eq!(membership.len(), 3);
    assert_eq!(membership[0].target, peer_target);
    assert_eq!(
        membership[0].display_name.as_deref(),
        Some("\u{2067}duplicate\u{2069}")
    );
    assert_eq!(membership[1].target, group_target);
    assert_eq!(membership[2].target, note_target);
    assert_eq!(
        membership
            .iter()
            .map(|item| match item.target.kind {
                LabelTargetKind::Peer => "peer",
                LabelTargetKind::Group => "group",
                LabelTargetKind::NoteToSelf => "note_to_self",
            })
            .collect::<Vec<_>>(),
        fixture["membership_target_kinds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );
    let any = node
        .filter_labels(
            vec![first.id.clone(), first.id.clone()],
            LabelMatchMode::Any,
        )
        .unwrap();
    assert_eq!(any.selected, vec![first.id.clone()]);
    assert_eq!(
        any.conversations
            .iter()
            .map(|item| match item.target.kind {
                LabelTargetKind::Peer => "peer",
                LabelTargetKind::Group => "group",
                LabelTargetKind::NoteToSelf => "note_to_self",
            })
            .collect::<Vec<_>>(),
        fixture["match_any_target_kinds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );
    let all = node
        .filter_labels(
            vec![first.id.clone(), second.id.clone()],
            LabelMatchMode::All,
        )
        .unwrap();
    assert_eq!(
        all.conversations
            .iter()
            .map(|item| match item.target.kind {
                LabelTargetKind::Peer => "peer",
                LabelTargetKind::Group => "group",
                LabelTargetKind::NoteToSelf => "note_to_self",
            })
            .collect::<Vec<_>>(),
        fixture["match_all_target_kinds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );

    let updated = node
        .update_label(
            first.id.clone(),
            fixture["renamed_name"].as_str().unwrap().to_owned(),
            fixture["renamed_color"].as_str().unwrap().to_owned(),
        )
        .unwrap();
    assert_eq!(updated.id, first.id);
    assert_eq!(updated.order, 0);
    assert_eq!(node.label_membership(first.id.clone()).unwrap().len(), 3);

    assert!(matches!(
        node.create_label(
            fixture["whitespace_only_name"].as_str().unwrap().to_owned(),
            "red".to_owned()
        ),
        Err(FfiError::Label {
            code: LabelErrorCode::InvalidName,
            ..
        })
    ));
    assert!(matches!(
        node.create_label(
            "valid".to_owned(),
            fixture["unsupported_color"].as_str().unwrap().to_owned()
        ),
        Err(FfiError::Label {
            code: LabelErrorCode::InvalidColor,
            ..
        })
    ));
    assert!(matches!(
        node.label(fixture["invalid_id"].as_str().unwrap().to_owned()),
        Err(FfiError::Label {
            code: LabelErrorCode::InvalidId,
            ..
        })
    ));
    assert!(matches!(
        node.assign_label(
            first.id.clone(),
            LabelTarget {
                kind: LabelTargetKind::NoteToSelf,
                id: Some("00".repeat(32)),
            },
        ),
        Err(FfiError::Label {
            code: LabelErrorCode::InvalidTarget,
            ..
        })
    ));
    assert!(matches!(
        node.delete_label(first.id.clone(), false),
        Err(FfiError::Label {
            code: LabelErrorCode::ConfirmationRequired,
            ..
        })
    ));
    assert_eq!(
        node.label_delete_assignment_count(first.id.clone())
            .unwrap(),
        fixture["expected_assignment_count"].as_u64().unwrap()
    );
    assert_eq!(
        node.delete_label(first.id.clone(), true).unwrap(),
        fixture["expected_assignment_count"].as_u64().unwrap()
    );
    let remaining = node.labels_for_conversation(note_target).unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, second.id);
    assert_eq!(remaining[0].name, second.name);
    assert_eq!(remaining[0].color, second.color);
    assert_eq!(remaining[0].order, 0);
    assert!(node.stale_labels().unwrap().is_empty());
    assert_eq!(node.status().unwrap().queued, queued_before);
    node.stop();
}

#[test]
fn private_folders_via_ffi_have_typed_parity_and_zero_delivery_work() {
    let fixture = folder_parity_fixture();
    let duplicate_name = fixture["duplicate_name"].as_str().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let recorder = Recorder::default();
    let node = KultNode::start(
        test_config(directory.path(), "folders"),
        Box::new(recorder.clone()),
    )
    .expect("node starts");
    let queued_before = node.status().unwrap().queued;
    let own_peer = node
        .add_contact(
            "\u{2067}duplicate\u{2069}".to_owned(),
            node.handshake_bundle().unwrap(),
            vec![],
        )
        .unwrap();
    let group = node
        .create_group("e\u{301} group".to_owned(), vec![])
        .unwrap();
    let first = node.create_folder(duplicate_name.to_owned()).unwrap();
    let second = node.create_folder(duplicate_name.to_owned()).unwrap();
    assert_ne!(first.id, second.id);
    assert_eq!(
        vec![first.order, second.order],
        fixture["expected_initial_orders"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_u64().unwrap() as u32)
            .collect::<Vec<_>>()
    );
    recorder.wait("folder event", |event| {
        matches!(event, Event::FoldersChanged)
    });
    let reordered = node
        .reorder_folders(vec![second.id.clone(), first.id.clone()])
        .unwrap();
    assert_eq!(reordered[0].id, second.id);
    assert_eq!(reordered[1].id, first.id);

    let peer_target = FolderTarget {
        kind: FolderTargetKind::Peer,
        id: Some(own_peer.clone()),
    };
    let group_target = FolderTarget {
        kind: FolderTargetKind::Group,
        id: Some(group.clone()),
    };
    let note_target = FolderTarget {
        kind: FolderTargetKind::NoteToSelf,
        id: None,
    };
    assert!(node
        .move_to_folder(first.id.clone(), peer_target.clone())
        .unwrap());
    assert!(node
        .move_to_folder(first.id.clone(), group_target.clone())
        .unwrap());
    assert!(node
        .move_to_folder(second.id.clone(), note_target.clone())
        .unwrap());
    assert!(!node
        .move_to_folder(second.id.clone(), note_target.clone())
        .unwrap());
    let members = node.folder_membership(first.id.clone()).unwrap();
    assert_eq!(members[0].target, peer_target);
    assert_eq!(members[1].target, group_target);

    let label = node
        .create_label("compose".to_owned(), "teal".to_owned())
        .unwrap();
    for target in [
        LabelTarget {
            kind: LabelTargetKind::Peer,
            id: Some(own_peer),
        },
        LabelTarget {
            kind: LabelTargetKind::Group,
            id: Some(group),
        },
    ] {
        node.assign_label(label.id.clone(), target).unwrap();
    }
    let composed = node
        .folder_conversations(
            FolderSelection {
                kind: FolderSelectionKind::Folder,
                id: Some(first.id.clone()),
            },
            vec![label.id],
            LabelMatchMode::Any,
        )
        .unwrap();
    assert_eq!(
        composed
            .conversations
            .iter()
            .map(|item| match item.target.kind {
                FolderTargetKind::Peer => "peer",
                FolderTargetKind::Group => "group",
                FolderTargetKind::NoteToSelf => "note_to_self",
            })
            .collect::<Vec<_>>(),
        fixture["folder_then_any_label_target_kinds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );
    assert!(node.unfile_conversation(peer_target.clone()).unwrap());
    assert!(!node.unfile_conversation(peer_target).unwrap());
    assert_eq!(
        node.conversation_folder(note_target.clone())
            .unwrap()
            .unwrap()
            .id,
        second.id
    );

    assert!(matches!(
        node.create_folder(fixture["whitespace_only_name"].as_str().unwrap().to_owned()),
        Err(FfiError::Folder {
            code: FolderErrorCode::InvalidName,
            ..
        })
    ));
    assert!(matches!(
        node.folder(fixture["invalid_id"].as_str().unwrap().to_owned()),
        Err(FfiError::Folder {
            code: FolderErrorCode::InvalidId,
            ..
        })
    ));
    assert!(matches!(
        node.reorder_folders(vec![second.id.clone(), second.id.clone()]),
        Err(FfiError::Folder {
            code: FolderErrorCode::InvalidOrder,
            ..
        })
    ));
    assert!(matches!(
        node.delete_folder(first.id.clone(), false),
        Err(FfiError::Folder {
            code: FolderErrorCode::ConfirmationRequired,
            ..
        })
    ));
    assert_eq!(
        node.folder_delete_assignment_count(first.id.clone())
            .unwrap(),
        fixture["expected_delete_assignment_count"]
            .as_u64()
            .unwrap()
    );
    assert_eq!(
        node.delete_folder(first.id.clone(), true).unwrap(),
        fixture["expected_delete_assignment_count"]
            .as_u64()
            .unwrap()
    );
    let replacement = node.create_folder(duplicate_name.to_owned()).unwrap();
    assert_ne!(replacement.id, first.id);
    assert!(node.folder_membership(replacement.id).unwrap().is_empty());
    assert!(node.stale_folders().unwrap().is_empty());
    assert_eq!(node.status().unwrap().queued, queued_before);
    node.stop();
}

#[test]
fn private_pins_via_ffi_have_typed_parity_restart_and_zero_delivery_work() {
    let fixture = pin_parity_fixture();
    let directory = tempfile::tempdir().unwrap();
    let recorder = Recorder::default();
    let node = KultNode::start(
        test_config(directory.path(), "pins"),
        Box::new(recorder.clone()),
    )
    .expect("node starts");
    let queued_before = node.status().unwrap().queued;
    let peer = node
        .add_contact(
            "same-looking name".to_owned(),
            node.handshake_bundle().unwrap(),
            vec![],
        )
        .unwrap();
    let group = node
        .create_group("same-looking name".to_owned(), vec![])
        .unwrap();
    node.send_note_to_self("latest local activity".to_owned())
        .unwrap();

    let peer_target = PinTarget {
        kind: PinTargetKind::Peer,
        id: Some(peer),
    };
    let group_target = PinTarget {
        kind: PinTargetKind::Group,
        id: Some(group),
    };
    let note_target = PinTarget {
        kind: PinTargetKind::NoteToSelf,
        id: None,
    };
    let appended = [
        peer_target.clone(),
        group_target.clone(),
        note_target.clone(),
    ];
    for target in &appended {
        assert!(node.pin_conversation(target.clone()).unwrap());
    }
    assert!(!node.pin_conversation(peer_target.clone()).unwrap());
    recorder.wait("pin event", |event| matches!(event, Event::PinsChanged));
    let pins = node.pins().unwrap();
    assert_eq!(
        pins.iter()
            .map(|pin| match pin.target.kind {
                PinTargetKind::Peer => "peer",
                PinTargetKind::Group => "group",
                PinTargetKind::NoteToSelf => "note_to_self",
            })
            .collect::<Vec<_>>(),
        fixture["initial_target_kinds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        pins.iter().map(|pin| pin.order).collect::<Vec<_>>(),
        fixture["expected_append_orders"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_u64().unwrap() as u32)
            .collect::<Vec<_>>()
    );
    assert!(
        node.pin_state(group_target.clone())
            .unwrap()
            .unwrap()
            .active
    );

    let reordered = vec![
        note_target.clone(),
        group_target.clone(),
        peer_target.clone(),
    ];
    assert_eq!(
        node.reorder_pins(reordered.clone())
            .unwrap()
            .into_iter()
            .map(|pin| pin.target)
            .collect::<Vec<_>>(),
        reordered
    );
    assert!(matches!(
        node.reorder_pins(vec![peer_target.clone()]),
        Err(FfiError::Pin {
            code: PinErrorCode::InvalidOrder,
            ..
        })
    ));
    assert!(matches!(
        node.cleanup_stale_pin(group_target.clone()),
        Err(FfiError::Pin {
            code: PinErrorCode::StalePinActive,
            ..
        })
    ));
    assert!(matches!(
        node.pin_conversation(PinTarget {
            kind: PinTargetKind::NoteToSelf,
            id: Some("00".repeat(32)),
        }),
        Err(FfiError::Pin {
            code: PinErrorCode::InvalidTarget,
            ..
        })
    ));
    let composed = node
        .pin_conversations(
            FolderSelection {
                kind: FolderSelectionKind::All,
                id: None,
            },
            vec![],
            LabelMatchMode::Any,
        )
        .unwrap();
    assert_eq!(
        composed
            .conversations
            .iter()
            .take(3)
            .map(|item| match item.target.kind {
                PinTargetKind::Peer => "peer",
                PinTargetKind::Group => "group",
                PinTargetKind::NoteToSelf => "note_to_self",
            })
            .collect::<Vec<_>>(),
        fixture["composed_pinned_target_kinds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect::<Vec<_>>()
    );
    assert!(composed
        .conversations
        .iter()
        .take(3)
        .all(|item| item.pinned));
    assert!(node.stale_pins().unwrap().is_empty());
    assert_eq!(node.status().unwrap().queued, queued_before);
    node.stop();

    let reopened = KultNode::start(
        test_config(directory.path(), "pins"),
        Box::new(Recorder::default()),
    )
    .expect("node reopens");
    assert_eq!(
        reopened
            .pins()
            .unwrap()
            .into_iter()
            .map(|pin| pin.target)
            .collect::<Vec<_>>(),
        reordered
    );
    assert!(reopened.unpin_conversation(peer_target.clone()).unwrap());
    assert!(!reopened.unpin_conversation(peer_target).unwrap());
    reopened.stop();
}

#[test]
fn two_nodes_message_via_ffi_only() {
    let ephemeral = ephemeral_parity_fixture();
    let hour = ephemeral["text_lifetimes"][1].as_u64().unwrap();
    assert_eq!(ephemeral["content_kind"], serde_json::json!(5));
    assert_eq!(
        ephemeral["terminal_reasons"],
        serde_json::json!(["expired", "consumed"])
    );
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

    let disappearing = alice
        .send_disappearing(
            bob_peer.clone(),
            "temporary through bindings".to_owned(),
            hour,
        )
        .unwrap();
    let temporary = b_rec.wait("bob's disappearing message", |event| {
        matches!(
            event,
            Event::MessageReceived {
                id,
                content_kind: ContentKind::DisappearingText,
                expires_at: Some(_),
                ..
            } if id == &disappearing
        )
    });
    let event_expiry = match temporary {
        Event::MessageReceived { expires_at, .. } => expires_at.unwrap(),
        other => panic!("wrong event: {other:?}"),
    };
    let temporary_history = bob.messages_with(alice_peer.clone()).unwrap();
    let temporary_row = temporary_history
        .iter()
        .find(|message| message.id == disappearing)
        .unwrap();
    assert_eq!(temporary_row.content_kind, ContentKind::DisappearingText);
    assert_eq!(temporary_row.expires_at, Some(event_expiry));

    // Authenticated capabilities have now crossed the same encrypted
    // session, so a second Text event is editable through exact UniFFI ids.
    std::thread::sleep(Duration::from_millis(300));
    let editable = alice
        .send(bob_peer.clone(), "original through bindings".to_owned())
        .unwrap();
    b_rec.wait("bob's canonical editable message", |event| {
        matches!(
            event,
            Event::MessageReceived {
                id,
                content_kind: ContentKind::Text,
                ..
            } if *id == editable
        )
    });
    a_rec.wait("editable message delivered", |event| {
        matches!(
            event,
            Event::DeliveryUpdated {
                id,
                state: DeliveryState::Delivered,
            } if *id == editable
        )
    });
    let wrong_author = alice
        .edit_message(
            bob_peer.clone(),
            bob_peer.clone(),
            editable.clone(),
            "forged".to_owned(),
        )
        .unwrap_err();
    assert!(wrong_author.to_string().contains("edit"));
    let edit = alice
        .edit_message(
            bob_peer.clone(),
            alice_peer.clone(),
            editable.clone(),
            "revised through bindings".to_owned(),
        )
        .unwrap();
    b_rec.wait("typed pairwise edit refresh", |event| {
        matches!(
            event,
            Event::MessageEdited {
                peer,
                target_content_id,
            } if peer == &alice_peer && target_content_id == &editable
        )
    });
    a_rec.wait("edit delivered", |event| {
        matches!(
            event,
            Event::DeliveryUpdated {
                id,
                state: DeliveryState::Delivered,
            } if id == &edit
        )
    });
    for history in [
        alice.messages_with(bob_peer.clone()).unwrap(),
        bob.messages_with(alice_peer.clone()).unwrap(),
    ] {
        assert_eq!(history.len(), 3, "edit events do not become chat rows");
        let message = history
            .iter()
            .find(|message| message.id == editable)
            .unwrap();
        assert!(message.edited);
        assert_eq!(message.edit_revision, 1);
        assert_eq!(message.body, "revised through bindings");
        assert_eq!(message.versions.len(), 2);
        assert_eq!(message.versions[0].body, "original through bindings");
        assert_eq!(message.versions[1].body, "revised through bindings");
    }

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
    a_rec.wait("sender observes attachment rejection", |event| {
        matches!(
            event,
            Event::AttachmentUpdated { attachment }
                if attachment.transfer_id == outbound[0].transfer_id
                    && attachment.state == AttachmentState::Rejected
        )
    });
    alice
        .cancel_attachment(outbound[0].transfer_id.clone())
        .unwrap();
    assert_eq!(
        alice.attachments().unwrap()[0].state,
        AttachmentState::Cancelled
    );

    let once_bytes = b"view-once through UniFFI";
    let once_source = dir.path().join("ffi-view-once.bin");
    std::fs::write(&once_source, once_bytes).unwrap();
    let once_id = alice
        .send_view_once_attachment(
            bob_peer.clone(),
            once_source.display().to_string(),
            "application/octet-stream".to_owned(),
            Some("reveal-once.bin".to_owned()),
            None,
            None,
            hour,
        )
        .unwrap();
    let once_offer = b_rec.wait("view-once offer", |event| {
        matches!(
            event,
            Event::AttachmentUpdated { attachment }
                if attachment.content_id == once_id
                    && attachment.direction == AttachmentDirection::Inbound
                    && attachment.view_once
        )
    });
    let once_transfer = match once_offer {
        Event::AttachmentUpdated { attachment } => {
            assert!(attachment.expires_at.is_some());
            attachment.transfer_id
        }
        other => panic!("wrong event: {other:?}"),
    };
    b_rec.wait("typed view-once message", |event| {
        matches!(
            event,
            Event::MessageReceived {
                id,
                content_kind: ContentKind::ViewOnceAttachment,
                expires_at: Some(_),
                ..
            } if id == &once_id
        )
    });
    bob.accept_attachment(once_transfer.clone()).unwrap();
    b_rec.wait("view-once completion", |event| {
        matches!(
            event,
            Event::AttachmentUpdated { attachment }
                if attachment.transfer_id == once_transfer
                    && attachment.state == AttachmentState::Complete
        )
    });
    assert!(bob
        .export_attachment(
            once_transfer.clone(),
            dir.path()
                .join("forbidden-view-once.bin")
                .display()
                .to_string(),
        )
        .is_err());
    let once_output = dir.path().join("ffi-view-once-output.bin");
    bob.consume_view_once_attachment(once_transfer.clone(), once_output.display().to_string())
        .unwrap();
    assert_eq!(std::fs::read(&once_output).unwrap(), once_bytes);
    assert!(bob
        .consume_view_once_attachment(
            once_transfer,
            dir.path()
                .join("ffi-view-once-second.bin")
                .display()
                .to_string(),
        )
        .is_err());

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
    let note_icon_target = CustomIconTarget {
        kind: CustomIconTargetKind::NoteToSelf,
        id: None,
    };
    let note_icon = alice
        .set_bundled_custom_icon(note_icon_target.clone(), "note".to_owned())
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
    assert_eq!(
        alice
            .custom_icon(note_icon_target)
            .unwrap()
            .expect("restored note icon")
            .bytes,
        note_icon.bytes
    );

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

#[test]
fn linked_device_ceremony_and_sync_via_ffi_only() {
    let dir = tempfile::tempdir().unwrap();
    let source_events = Recorder::default();
    let target_events = Recorder::default();
    let source = KultNode::start(
        test_config(dir.path(), "device-source"),
        Box::new(source_events.clone()),
    )
    .unwrap();
    let target = KultNode::start(
        test_config(dir.path(), "device-target"),
        Box::new(target_events.clone()),
    )
    .unwrap();
    source
        .send_note_to_self("source-only history".to_owned())
        .unwrap();

    let source_device = source.device_id().unwrap();
    let target_device = target.device_id().unwrap();
    let offer = source.begin_device_link().unwrap();
    let accepted = target
        .accept_device_link(offer, "Laptop".to_owned())
        .unwrap();
    assert_eq!(accepted.confirmation_code.len(), 6);
    assert_eq!(
        source
            .device_link_confirmation_code(accepted.response.clone())
            .unwrap(),
        accepted.confirmation_code
    );
    let package = source
        .approve_device_link(
            accepted.response,
            DeviceLinkSelection {
                contacts: false,
                organization: false,
                history: false,
            },
            true,
        )
        .unwrap();
    target.complete_device_link(package, true).unwrap();
    assert_eq!(source.peer(), target.peer());
    assert_ne!(source_device, target_device);
    assert!(target.note_to_self_messages().unwrap().is_empty());
    assert_eq!(source.linked_devices().unwrap().len(), 2);
    assert_eq!(target.linked_devices().unwrap().len(), 2);
    target_events.wait("device link completed", |event| {
        matches!(event, Event::DeviceLinkCompleted { device, .. } if device == &target_device)
    });

    source
        .rename_linked_device(target_device.clone(), "Travel laptop".to_owned())
        .unwrap();
    let sync = source.export_device_sync(target_device.clone()).unwrap();
    target.import_device_sync(sync).unwrap();
    assert!(target
        .linked_devices()
        .unwrap()
        .iter()
        .any(|device| device.id == target_device && device.name == "Travel laptop"));
    assert!(source
        .message_device_deliveries("00".repeat(16))
        .unwrap()
        .is_empty());

    source.stop();
    target.stop();
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

    let temporary_group = alice
        .send_group_disappearing(
            group.clone(),
            "temporary group through bindings".to_owned(),
            3_600,
        )
        .unwrap();
    let temporary_group_event = b_rec.wait("bob's disappearing group message", |event| {
        matches!(
            event,
            Event::GroupMessageReceived {
                id,
                content_kind: ContentKind::DisappearingText,
                expires_at: Some(_),
                ..
            } if id == &temporary_group
        )
    });
    let temporary_group_expiry = match temporary_group_event {
        Event::GroupMessageReceived { expires_at, .. } => expires_at.unwrap(),
        other => panic!("wrong event: {other:?}"),
    };
    let temporary_group_row = bob
        .group_messages(group.clone())
        .unwrap()
        .into_iter()
        .find(|message| message.id == temporary_group)
        .unwrap();
    assert_eq!(
        temporary_group_row.content_kind,
        ContentKind::DisappearingText
    );
    assert_eq!(temporary_group_row.expires_at, Some(temporary_group_expiry));

    std::thread::sleep(Duration::from_millis(300));
    let editable = alice
        .send_group(group.clone(), "editable group original".to_owned())
        .unwrap();
    b_rec.wait("bob's editable group Text", |event| {
        matches!(
            event,
            Event::GroupMessageReceived {
                id,
                content_kind: ContentKind::Text,
                ..
            } if id == &editable
        )
    });
    a_rec.wait("editable group copy delivered", |event| {
        matches!(
            event,
            Event::GroupDeliveryUpdated {
                id,
                peer,
                state: DeliveryState::Delivered,
            } if id == &editable && peer == &bob_peer
        )
    });
    let group_edit = alice
        .edit_group_message(
            group.clone(),
            alice_peer.clone(),
            editable.clone(),
            "editable group revised".to_owned(),
        )
        .unwrap();
    b_rec.wait("typed group edit refresh", |event| {
        matches!(
            event,
            Event::GroupMessageEdited {
                group: event_group,
                sender,
                target_content_id,
            } if event_group == &group && sender == &alice_peer && target_content_id == &editable
        )
    });
    a_rec.wait("group edit delivered", |event| {
        matches!(
            event,
            Event::GroupDeliveryUpdated {
                id,
                peer,
                state: DeliveryState::Delivered,
            } if id == &group_edit && peer == &bob_peer
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
        assert_eq!(message.body, "editable group revised");
        assert!(message.edited);
        assert_eq!(message.edit_revision, 1);
        assert_eq!(message.versions.len(), 2);
    }

    let capability = mention_capability(&alice, &group);
    let history_before_invalid = alice.group_messages(group.clone()).unwrap().len();
    let error = alice
        .send_group_mention(
            group.clone(),
            "👩".to_owned(),
            vec![MentionSpan {
                start: 1,
                end: 4,
                target: bob_peer.clone(),
            }],
            capability.review_token.clone(),
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("invalid group mention"), "got: {error}");
    assert_eq!(
        alice.group_messages(group.clone()).unwrap().len(),
        history_before_invalid,
        "invalid native byte ranges are rejected before persistence or send"
    );

    let mention_id = alice
        .send_group_mention(
            group.clone(),
            "hi @bob 👋".to_owned(),
            vec![MentionSpan {
                start: 3,
                end: 7,
                target: bob_peer.clone(),
            }],
            capability.review_token,
        )
        .unwrap();
    let mention_event = b_rec.wait("bob's semantic mention", |event| {
        matches!(event, Event::GroupMessageReceived {
            id,
            body,
            content_kind: ContentKind::Mention,
            mention_spans,
            ..
        } if *id == mention_id
            && body == "hi @bob 👋"
            && mention_spans == &[MentionSpan {
                start: 3,
                end: 7,
                target: bob_peer.clone(),
            }])
    });
    assert!(matches!(mention_event, Event::GroupMessageReceived { .. }));
    b_rec.wait(
        "local mention signal",
        |event| matches!(event, Event::MentionReceived { id } if *id == mention_id),
    );
    let history = alice.group_messages(group.clone()).unwrap();
    let mention = history
        .iter()
        .find(|message| message.id == mention_id)
        .unwrap();
    assert_eq!(mention.body, "hi @bob 👋");
    assert_eq!(mention.content_kind, ContentKind::Mention);
    assert_eq!(mention.mention_spans.len(), 1);
    assert_eq!(mention.mention_spans[0].target, bob_peer);

    let error = alice
        .send_group_mention(
            group.clone(),
            "hi @bob".to_owned(),
            vec![MentionSpan {
                start: 3,
                end: 7,
                target: "bob".to_owned(),
            }],
            "00".repeat(16),
        )
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("peer") && error.contains("hex"),
        "got: {error}"
    );

    // C5 poll creation, visible authenticated vote revisions, and creator
    // closure use the same stable-id model through generated bindings.
    let chat_rows_before_poll = alice.group_messages(group.clone()).unwrap().len();
    let poll_id = alice
        .create_group_poll(
            group.clone(),
            "Lunch? 👩🏽‍🚀".to_owned(),
            vec!["Soup".to_owned(), "Salad".to_owned()],
        )
        .unwrap();
    b_rec.wait("group poll creation", |event| {
        matches!(
            event,
            Event::PollUpdated {
                group: event_group,
                poll_author,
                poll_id: event_poll,
            } if event_group == &group && poll_author == &alice_peer && event_poll == &poll_id
        )
    });
    let poll = bob.group_polls(group.clone()).unwrap().remove(0);
    assert_eq!(poll.question, "Lunch? 👩🏽‍🚀");
    assert!(poll.votes_visible);
    assert!(!poll.anonymous);
    assert_eq!(poll.close_policy, "manual_creator_snapshot");
    let soup = poll.options[0].id.clone();
    let salad = poll.options[1].id.clone();
    assert!(bob
        .vote_group_poll(
            group.clone(),
            alice_peer.clone(),
            "bad-id".to_owned(),
            soup.clone(),
        )
        .unwrap_err()
        .to_string()
        .contains("hex"));

    bob.vote_group_poll(group.clone(), alice_peer.clone(), poll_id.clone(), soup)
        .unwrap();
    a_rec.wait_count(
        "first poll vote",
        |event| matches!(event, Event::PollUpdated { poll_id: id, .. } if id == &poll_id),
        1,
    );
    bob.vote_group_poll(
        group.clone(),
        alice_peer.clone(),
        poll_id.clone(),
        salad.clone(),
    )
    .unwrap();
    a_rec.wait_count(
        "changed poll vote",
        |event| matches!(event, Event::PollUpdated { poll_id: id, .. } if id == &poll_id),
        2,
    );
    for poll in [
        poll_revision(&alice, &group, &poll_id, 2),
        poll_revision(&bob, &group, &poll_id, 2),
    ] {
        assert_eq!(poll.votes.len(), 1);
        assert_eq!(poll.votes[0].voter, bob_peer);
        assert_eq!(poll.votes[0].option_id, salad);
        assert_eq!(poll.options[1].votes, 1);
    }
    let close_id = alice
        .close_group_poll(group.clone(), alice_peer.clone(), poll_id.clone())
        .unwrap();
    let final_poll = closed_poll(&bob, &group, &poll_id);
    assert_eq!(final_poll.close_event_id, Some(close_id));
    assert_eq!(final_poll.votes[0].option_id, salad);
    assert!(bob
        .vote_group_poll(
            group.clone(),
            alice_peer.clone(),
            poll_id.clone(),
            final_poll.options[0].id.clone(),
        )
        .unwrap_err()
        .to_string()
        .contains("closed"));
    assert_eq!(
        alice.group_messages(group.clone()).unwrap().len(),
        chat_rows_before_poll,
        "poll events never become empty group-message rows"
    );

    // C6 is exposed without raw protocol bytes: legacy upgrade, exact roles,
    // admin request results, signed owner moderation, and ownership transfer.
    let legacy_authority = alice.group_authority(group.clone()).unwrap();
    assert!(!legacy_authority.signed);
    assert_eq!(legacy_authority.owner, alice_peer);
    assert_eq!(legacy_authority.my_role, Some(GroupRole::Owner));
    let upgrade_generation = legacy_authority.generation + 1;
    alice.upgrade_group_authority(group.clone()).unwrap();
    let upgraded = authority_generation(&bob, &group, upgrade_generation);
    assert_eq!(upgraded.owner, alice_peer);
    assert_eq!(upgraded.my_role, Some(GroupRole::Member));
    assert_eq!(upgraded.members.len(), 2);

    alice
        .set_group_role(group.clone(), bob_peer.clone(), GroupRole::Admin)
        .unwrap();
    let admin_generation = upgrade_generation + 1;
    assert_eq!(
        authority_generation(&bob, &group, admin_generation).my_role,
        Some(GroupRole::Admin)
    );
    let error = bob
        .set_group_role(group.clone(), alice_peer.clone(), GroupRole::Member)
        .unwrap_err()
        .to_string();
    assert!(error.contains("owner"), "got: {error}");

    let rename_request = bob
        .rename_group(group.clone(), "authority trail crew".to_owned())
        .unwrap();
    let rename_generation = admin_generation + 1;
    let rename_result = b_rec.wait("admin rename result", |event| {
        matches!(event, Event::GroupAdminRequestResolved {
            request_id,
            accepted: true,
            generation,
            state_id: Some(_),
            reason: 0,
            ..
        } if request_id == &rename_request && *generation == rename_generation)
    });
    assert!(matches!(
        rename_result,
        Event::GroupAdminRequestResolved { accepted: true, .. }
    ));
    authority_generation(&bob, &group, rename_generation);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if bob
            .groups()
            .unwrap()
            .iter()
            .any(|candidate| candidate.id == group && candidate.name == "authority trail crew")
        {
            break;
        }
        assert!(Instant::now() < deadline, "group rename did not converge");
        std::thread::sleep(Duration::from_millis(50));
    }

    let moderated_poll = alice
        .create_group_poll(
            group.clone(),
            "Close for weather?".to_owned(),
            vec!["Keep open".to_owned(), "Close".to_owned()],
        )
        .unwrap();
    b_rec.wait(
        "moderated poll creation",
        |event| matches!(event, Event::PollUpdated { poll_id, .. } if poll_id == &moderated_poll),
    );
    let moderation_request = bob
        .moderate_group_poll_close(group.clone(), alice_peer.clone(), moderated_poll.clone())
        .unwrap();
    let moderation_generation = rename_generation + 1;
    b_rec.wait("admin moderation result", |event| {
        matches!(event, Event::GroupAdminRequestResolved {
            request_id,
            accepted: true,
            generation,
            reason: 0,
            ..
        } if request_id == &moderation_request && *generation == moderation_generation)
    });
    let moderated = closed_poll(&bob, &group, &moderated_poll);
    assert_eq!(moderated.moderated_by, Some(alice_peer.clone()));
    assert_eq!(moderated.close_policy, "signed_owner_snapshot");

    alice
        .transfer_group_owner(group.clone(), bob_peer.clone())
        .unwrap();
    let bob_owner_generation = moderation_generation + 1;
    let bob_owner = authority_generation(&bob, &group, bob_owner_generation);
    assert_eq!(bob_owner.owner, bob_peer);
    assert_eq!(bob_owner.owner_epoch, 1);
    assert_eq!(bob_owner.my_role, Some(GroupRole::Owner));
    let error = bob.leave_group(group.clone()).unwrap_err().to_string();
    assert!(error.contains("owner"), "got: {error}");

    bob.transfer_group_owner(group.clone(), alice_peer.clone())
        .unwrap();
    let alice_owner_generation = bob_owner_generation + 1;
    let alice_owner = authority_generation(&alice, &group, alice_owner_generation);
    assert_eq!(alice_owner.owner, alice_peer);
    assert_eq!(alice_owner.owner_epoch, 2);
    alice
        .set_group_role(group.clone(), bob_peer.clone(), GroupRole::Member)
        .unwrap();
    authority_generation(&bob, &group, alice_owner_generation + 1);

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
    wait_group_presence(&bob, &group, false);
    assert!(bob.groups().unwrap().is_empty());

    let leave_group = alice
        .create_group("short trip".to_owned(), vec![bob_peer])
        .unwrap();
    wait_group_presence(&bob, &leave_group, true);
    bob.leave_group(leave_group).unwrap();

    alice.stop();
    bob.stop();
}
