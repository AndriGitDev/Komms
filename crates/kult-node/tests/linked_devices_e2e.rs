//! C2 proximate linking, selected initial transfer, convergence, restart,
//! and revocation exclusion through the real sealed store boundary.

use kult_crypto::KdfProfile;
use std::io::Cursor;
use std::sync::Arc;

use kult_node::{
    AttachmentMetadata, ContentStatus, DeviceLinkSelection, Event, LinkedDeviceInfo, Node,
    NodeError,
};
use kult_store::MediaTransferState;
use kult_transport::{DeliveryHint, SneakernetTransport};
use rand::{rngs::StdRng, SeedableRng};
use tempfile::TempDir;

fn profile() -> KdfProfile {
    KdfProfile {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    }
}

fn create(dir: &TempDir, name: &str, rng: &mut StdRng) -> (std::path::PathBuf, Node) {
    let path = dir.path().join(format!("{name}.db"));
    let node = Node::create(&path, b"pass", profile(), rng).unwrap();
    (path, node)
}

fn link(
    source: &mut Node,
    target: &mut Node,
    target_name: &str,
    selection: DeviceLinkSelection,
    now: u64,
    rng: &mut StdRng,
) {
    let offer = source.begin_device_link(now, rng).unwrap();
    let (response, target_code) = target
        .accept_device_link(&offer, target_name, now + 1, rng)
        .unwrap();
    let source_code = source.device_link_confirmation_code(&response).unwrap();
    assert_eq!(source_code, target_code);
    let package = source
        .approve_device_link(&response, selection, true, now + 2, rng)
        .unwrap();
    target
        .complete_device_link(&package, true, now + 3, rng)
        .unwrap();
}

fn authority(devices: Vec<LinkedDeviceInfo>) -> Vec<([u8; 32], String, u64, Option<u64>)> {
    devices
        .into_iter()
        .map(|device| (device.id, device.name, device.last_seen, device.revoked_at))
        .collect()
}

#[test]
fn three_devices_link_transfer_converge_restart_and_revoke() {
    let dir = TempDir::new().unwrap();
    let mut rng = StdRng::seed_from_u64(91);
    let (source_path, mut source) = create(&dir, "source", &mut rng);
    let (laptop_path, mut laptop) = create(&dir, "laptop", &mut rng);
    let (tablet_path, mut tablet) = create(&dir, "tablet", &mut rng);
    let (_, mut contact) = create(&dir, "contact", &mut rng);

    let contact_bundle = contact.handshake_bundle(100, &mut rng).unwrap();
    let contact_id = source
        .add_contact("Alice", &contact_bundle, &[], 100, &mut rng)
        .unwrap();
    source
        .note_to_self_send("selected history", 101, &mut rng)
        .unwrap();

    let account = source.peer_id();
    let source_device = source.device_id();
    let laptop_device = laptop.device_id();
    assert_ne!(account, source_device);
    assert_ne!(source_device, laptop_device);

    link(
        &mut source,
        &mut laptop,
        "Laptop",
        DeviceLinkSelection::default(),
        110,
        &mut rng,
    );
    assert_eq!(laptop.peer_id(), account);
    assert_eq!(laptop.device_id(), laptop_device);
    assert_eq!(laptop.contacts().unwrap()[0].peer, contact_id);
    assert_eq!(laptop.note_to_self_messages().unwrap().len(), 1);
    assert_eq!(source.linked_devices().len(), 2);
    assert_eq!(
        authority(source.linked_devices()),
        authority(laptop.linked_devices())
    );

    // Link a third partitioned device through the source. The first target
    // learns the new signed manifest on rejoin without any cloud log.
    let tablet_device = tablet.device_id();
    link(
        &mut source,
        &mut tablet,
        "Tablet",
        DeviceLinkSelection {
            contacts: false,
            organization: false,
            history: false,
        },
        120,
        &mut rng,
    );
    assert_eq!(tablet.peer_id(), account);
    assert!(tablet.contacts().unwrap().is_empty());
    assert!(tablet.note_to_self_messages().unwrap().is_empty());
    let source_to_laptop = source.export_device_sync(&laptop_device, &mut rng).unwrap();
    assert!(
        laptop
            .import_device_sync(&source_to_laptop, &mut rng)
            .unwrap()
            > 0
    );
    assert_eq!(laptop.linked_devices().len(), 3);

    // Concurrent account state and history changes converge by signed event
    // order after a partition, independent of exchange order.
    source
        .rename_contact(&contact_id, "Alice on phone", true, &mut rng)
        .unwrap();
    laptop
        .rename_contact(&contact_id, "Alice on laptop", true, &mut rng)
        .unwrap();
    source
        .note_to_self_send("phone partition", 130, &mut rng)
        .unwrap();
    laptop
        .note_to_self_send("laptop partition", 131, &mut rng)
        .unwrap();
    let from_source = source.export_device_sync(&laptop_device, &mut rng).unwrap();
    let from_laptop = laptop.export_device_sync(&source_device, &mut rng).unwrap();
    source.import_device_sync(&from_laptop, &mut rng).unwrap();
    laptop.import_device_sync(&from_source, &mut rng).unwrap();
    assert_eq!(
        source.contacts().unwrap()[0].name,
        laptop.contacts().unwrap()[0].name
    );
    assert_eq!(source.note_to_self_messages().unwrap().len(), 3);
    assert_eq!(
        source.note_to_self_messages().unwrap(),
        laptop.note_to_self_messages().unwrap()
    );

    // Concurrent generation forks converge by the signed state-id order.
    source
        .rename_linked_device(&tablet_device, "Travel tablet", &mut rng)
        .unwrap();
    laptop
        .rename_linked_device(&source_device, "Home desktop", &mut rng)
        .unwrap();
    let a = source.export_device_sync(&laptop_device, &mut rng).unwrap();
    let b = laptop.export_device_sync(&source_device, &mut rng).unwrap();
    let source_result = source.import_device_sync(&b, &mut rng);
    let laptop_result = laptop.import_device_sync(&a, &mut rng);
    assert!(source_result.is_ok() ^ laptop_result.is_ok());
    if source_result.is_ok() {
        let final_state = source.export_device_sync(&laptop_device, &mut rng).unwrap();
        laptop.import_device_sync(&final_state, &mut rng).unwrap();
    } else {
        let final_state = laptop.export_device_sync(&source_device, &mut rng).unwrap();
        source.import_device_sync(&final_state, &mut rng).unwrap();
    }
    assert_eq!(
        authority(source.linked_devices()),
        authority(laptop.linked_devices())
    );

    drop(contact);
    drop(source);
    drop(laptop);
    drop(tablet);
    let mut source = Node::open(&source_path, b"pass").unwrap();
    let laptop = Node::open(&laptop_path, b"pass").unwrap();
    let tablet = Node::open(&tablet_path, b"pass").unwrap();
    assert_eq!(source.peer_id(), laptop.peer_id());
    assert_eq!(source.peer_id(), tablet.peer_id());
    assert_eq!(
        authority(source.linked_devices()),
        authority(laptop.linked_devices())
    );

    source
        .revoke_linked_device(&tablet_device, 200, &mut rng)
        .unwrap();
    let tablet_row = source
        .linked_devices()
        .into_iter()
        .find(|device| device.id == tablet_device)
        .unwrap();
    assert_eq!(tablet_row.revoked_at, Some(200));
    assert!(matches!(
        source.export_device_sync(&tablet_device, &mut rng),
        Err(NodeError::UnknownLinkedDevice)
    ));
    assert!(matches!(
        source.revoke_linked_device(&source_device, 201, &mut rng),
        Err(NodeError::CannotRevokeCurrentDevice)
    ));
}

#[test]
fn link_requires_pristine_target_and_explicit_confirmation() {
    let dir = TempDir::new().unwrap();
    let mut rng = StdRng::seed_from_u64(92);
    let (_, mut source) = create(&dir, "source", &mut rng);
    let (_, mut target) = create(&dir, "target", &mut rng);
    target
        .note_to_self_send("local state", 10, &mut rng)
        .unwrap();
    let offer = source.begin_device_link(20, &mut rng).unwrap();
    assert!(matches!(
        target.accept_device_link(&offer, "Target", 21, &mut rng),
        Err(NodeError::DeviceLinkTargetNotEmpty)
    ));

    let (_, mut empty) = create(&dir, "empty", &mut rng);
    let (response, _) = empty
        .accept_device_link(&offer, "Empty", 21, &mut rng)
        .unwrap();
    assert!(source
        .approve_device_link(
            &response,
            DeviceLinkSelection::default(),
            false,
            22,
            &mut rng
        )
        .is_err());
}

#[test]
fn backup_recovery_mints_new_device_and_never_resurrects_old_credentials() {
    let dir = TempDir::new().unwrap();
    let mut rng = StdRng::seed_from_u64(93);
    let (_, mut source) = create(&dir, "source", &mut rng);
    let (_, mut laptop) = create(&dir, "laptop", &mut rng);
    link(
        &mut source,
        &mut laptop,
        "Laptop",
        DeviceLinkSelection::default(),
        100,
        &mut rng,
    );
    let old_ids: Vec<[u8; 32]> = source
        .linked_devices()
        .into_iter()
        .filter(|device| device.revoked_at.is_none())
        .map(|device| device.id)
        .collect();
    let account = source.peer_id();
    let (backup, mnemonic) = source.export_backup(200, &mut rng).unwrap();
    assert_eq!(&backup[..4], b"KKR7");
    let recovered_path = dir.path().join("recovered.db");
    let recovered = Node::restore(
        &recovered_path,
        &backup,
        &mnemonic,
        b"new-pass",
        profile(),
        &mut rng,
    )
    .unwrap();
    assert_eq!(recovered.peer_id(), account);
    assert!(!old_ids.contains(&recovered.device_id()));
    for old in old_ids {
        let row = recovered
            .linked_devices()
            .into_iter()
            .find(|device| device.id == old)
            .unwrap();
        assert_eq!(row.revoked_at, Some(200));
    }
    assert_eq!(
        recovered
            .linked_devices()
            .iter()
            .filter(|device| device.revoked_at.is_none())
            .count(),
        1
    );
}

#[tokio::test]
async fn linked_devices_use_distinct_external_ratchet_sessions_for_one_account() {
    let dir = TempDir::new().unwrap();
    let mut rng = StdRng::seed_from_u64(94);
    let (_, mut phone) = create(&dir, "phone", &mut rng);
    let (_, mut laptop) = create(&dir, "laptop", &mut rng);
    let (carol_path, mut carol) = create(&dir, "carol", &mut rng);
    let phone_spool = dir.path().join("phone-spool");
    let laptop_spool = dir.path().join("laptop-spool");
    let carol_spool = dir.path().join("carol-spool");
    phone.add_transport(Arc::new(SneakernetTransport::new(&phone_spool).unwrap()));
    laptop.add_transport(Arc::new(SneakernetTransport::new(&laptop_spool).unwrap()));
    carol.add_transport(Arc::new(SneakernetTransport::new(&carol_spool).unwrap()));

    // Establish the legacy-compatible primary-device session first.
    let phone_bundle = phone.handshake_bundle(100, &mut rng).unwrap();
    let carol_bundle = carol.handshake_bundle(100, &mut rng).unwrap();
    let carol_id = phone
        .add_contact(
            "Carol",
            &carol_bundle,
            &[DeliveryHint::Spool(carol_spool.clone())],
            100,
            &mut rng,
        )
        .unwrap();
    let account = carol
        .add_contact(
            "Phone account",
            &phone_bundle,
            &[DeliveryHint::Spool(phone_spool.clone())],
            100,
            &mut rng,
        )
        .unwrap();
    phone
        .send_message(&carol_id, b"from phone", 101, &mut rng)
        .unwrap();
    phone.tick(102, &mut rng).await.unwrap();
    carol.tick(103, &mut rng).await.unwrap();
    phone.tick(104, &mut rng).await.unwrap();
    let group = phone
        .create_group("Shared account group", &[carol_id], &mut rng)
        .unwrap();
    phone.tick(106, &mut rng).await.unwrap();
    carol.tick(107, &mut rng).await.unwrap();
    phone.tick(108, &mut rng).await.unwrap();

    // The target imports contacts but no ratchets, then advertises a
    // certificate-bound device bundle for a second independent session.
    link(
        &mut phone,
        &mut laptop,
        "Laptop",
        DeviceLinkSelection::default(),
        110,
        &mut rng,
    );
    let laptop_bundle = laptop.handshake_bundle(120, &mut rng).unwrap();
    assert_eq!(
        carol
            .add_contact(
                "Same account",
                &laptop_bundle,
                &[DeliveryHint::Spool(laptop_spool.clone())],
                120,
                &mut rng,
            )
            .unwrap(),
        account
    );
    let laptop_message = laptop
        .send_message(&carol_id, b"from laptop", 121, &mut rng)
        .unwrap();
    let laptop_events = laptop.tick(122, &mut rng).await.unwrap();
    assert_eq!(laptop.queued().unwrap(), 0, "laptop: {laptop_events:?}");
    let events = carol.tick(123, &mut rng).await.unwrap();
    assert!(
        events.iter().any(|event| matches!(
            event,
            Event::MessageReceived { peer, body, .. }
                if *peer == account && body == b"from laptop"
        )),
        "events: {events:?}"
    );
    let receipt = laptop.tick(124, &mut rng).await.unwrap();
    assert!(receipt.iter().any(|event| matches!(
        event,
        Event::DeliveryUpdated { id, state: kult_store::DeliveryState::Delivered }
            if *id == laptop_message
    )));

    // The transferred group owns a fresh sender chain on the laptop. Carol
    // retains that chain alongside the phone's chain under the same stable
    // account member instead of letting the second announce replace it.
    laptop.tick(125, &mut rng).await.unwrap();
    carol.tick(126, &mut rng).await.unwrap();
    laptop.tick(127, &mut rng).await.unwrap();
    phone
        .group_send(&group, b"phone group chain", 128, &mut rng)
        .unwrap();
    laptop
        .group_send(&group, b"laptop group chain", 128, &mut rng)
        .unwrap();
    phone.tick(129, &mut rng).await.unwrap();
    laptop.tick(129, &mut rng).await.unwrap();
    let group_events = carol.tick(130, &mut rng).await.unwrap();
    let group_bodies: Vec<Vec<u8>> = group_events
        .iter()
        .filter_map(|event| match event {
            Event::GroupMessageReceived { body, .. } => Some(body.clone()),
            _ => None,
        })
        .collect();
    assert!(
        group_bodies.iter().any(|body| body == b"phone group chain")
            && group_bodies
                .iter()
                .any(|body| body == b"laptop group chain"),
        "group events: {group_events:?}"
    );

    // The primary session remains decryptable after the second device's
    // handshake instead of being overwritten under the shared account id.
    let editable = phone
        .send_message(&carol_id, b"phone still works", 130, &mut rng)
        .unwrap();
    phone.tick(131, &mut rng).await.unwrap();
    let events = carol.tick(132, &mut rng).await.unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        Event::MessageReceived { peer, body, .. }
            if *peer == account && body == b"phone still works"
    )));
    phone.tick(133, &mut rng).await.unwrap();

    // Immutable edits and poll events are convergent account history, not
    // ratchet state: a sibling device learns them from the authenticated
    // device log and derives the identical read model.
    phone
        .edit_message(
            &carol_id,
            phone.peer_id(),
            editable,
            "phone still works — edited",
            134,
            &mut rng,
        )
        .unwrap();
    let edit_sync = phone
        .export_device_sync(&laptop.device_id(), &mut rng)
        .unwrap();
    laptop.import_device_sync(&edit_sync, &mut rng).unwrap();
    let phone_edited = phone
        .resolved_messages_with(&carol_id)
        .unwrap()
        .into_iter()
        .find(|message| message.record.id == editable)
        .unwrap();
    let laptop_edited = laptop
        .resolved_messages_with(&carol_id)
        .unwrap()
        .into_iter()
        .find(|message| message.record.id == editable)
        .unwrap();
    assert_eq!(phone_edited.edited, laptop_edited.edited);
    assert_eq!(
        phone_edited.winning_revision,
        laptop_edited.winning_revision
    );
    assert_eq!(phone_edited.versions, laptop_edited.versions);
    assert_eq!(phone_edited.record.body, laptop_edited.record.body);
    assert!(laptop_edited.edited);

    let poll_id = phone
        .group_create_poll(
            &group,
            "Which linked device?",
            &["Phone".to_owned(), "Laptop".to_owned()],
            135,
            &mut rng,
        )
        .unwrap();
    let poll_sync = phone
        .export_device_sync(&laptop.device_id(), &mut rng)
        .unwrap();
    laptop.import_device_sync(&poll_sync, &mut rng).unwrap();
    assert!(phone
        .group_polls(&group)
        .unwrap()
        .iter()
        .any(|poll| poll.id == poll_id));
    assert_eq!(
        phone.group_polls(&group).unwrap(),
        laptop.group_polls(&group).unwrap()
    );

    let fanout = carol
        .send_message(&account, b"to every device", 140, &mut rng)
        .unwrap();
    carol.tick(141, &mut rng).await.unwrap();
    let initial_deliveries = carol.message_device_deliveries(&fanout).unwrap();
    assert_eq!(initial_deliveries.len(), 2, "fan-out routes");
    assert!(
        initial_deliveries
            .iter()
            .all(|delivery| delivery.state == kult_store::DeliveryState::Sent),
        "deliveries: {initial_deliveries:?}"
    );
    let phone_files = std::fs::read_dir(&phone_spool).unwrap().count();
    let laptop_files = std::fs::read_dir(&laptop_spool).unwrap().count();
    assert!(
        phone_files > 0,
        "phone spool empty; laptop has {laptop_files}; deliveries {initial_deliveries:?}; account {account:?}; laptop {:?}",
        laptop.device_id()
    );
    let mut phone_events = phone.tick(142, &mut rng).await.unwrap();
    phone_events.extend(phone.tick(143, &mut rng).await.unwrap());
    let laptop_events = laptop.tick(142, &mut rng).await.unwrap();
    assert!(
        phone_events.iter().any(|event| matches!(
            event,
            Event::MessageReceived { body, .. } if body == b"to every device"
        )),
        "phone events: {phone_events:?}; laptop events: {laptop_events:?}; history: {:?}",
        phone.messages_with(&carol_id).unwrap(),
    );
    assert!(laptop_events.iter().any(|event| matches!(
        event,
        Event::MessageReceived { body, .. } if body == b"to every device"
    )));
    carol.tick(143, &mut rng).await.unwrap();
    let deliveries = carol.message_device_deliveries(&fanout).unwrap();
    assert_eq!(deliveries.len(), 2);
    assert!(deliveries
        .iter()
        .all(|delivery| delivery.state == kult_store::DeliveryState::Delivered));

    // Attachment manifests use the same account-to-device fan-out, while
    // bulk requests and chunks stay on the exact authenticated device
    // ratchet. Either installation can accept its independent local offer.
    let attachment_bytes = b"linked-device attachment".to_vec();
    let attachment = carol
        .send_attachment(
            &account,
            &AttachmentMetadata {
                media_type: "application/octet-stream".to_owned(),
                filename: Some("linked.bin".to_owned()),
            },
            &mut Cursor::new(&attachment_bytes),
            144,
            &mut rng,
        )
        .unwrap();
    carol.tick(145, &mut rng).await.unwrap();
    let phone_events = phone.tick(146, &mut rng).await.unwrap();
    let laptop_events = laptop.tick(146, &mut rng).await.unwrap();
    let offer = |events: &[Event]| {
        events.iter().find_map(|event| match event {
            Event::MessageReceived {
                content: ContentStatus::Attachment { id, transfer },
                ..
            } if *id == attachment => Some(*transfer),
            _ => None,
        })
    };
    assert!(offer(&phone_events).is_some(), "phone: {phone_events:?}");
    let laptop_transfer = offer(&laptop_events).expect("laptop attachment offer");
    let attachment_deliveries = carol.message_device_deliveries(&attachment).unwrap();
    assert_eq!(attachment_deliveries.len(), 2);
    assert!(attachment_deliveries
        .iter()
        .all(|delivery| delivery.state == kult_store::DeliveryState::Sent));

    laptop
        .accept_attachment(&laptop_transfer, 147, &mut rng)
        .unwrap();
    laptop.tick(148, &mut rng).await.unwrap();
    carol.tick(149, &mut rng).await.unwrap();
    laptop.tick(150, &mut rng).await.unwrap();
    let received = laptop
        .attachments()
        .unwrap()
        .into_iter()
        .find(|item| item.transfer_id == laptop_transfer)
        .unwrap();
    assert_eq!(received.state, MediaTransferState::Complete);
    let mut exported = Vec::new();
    laptop
        .export_attachment(&laptop_transfer, &mut exported)
        .unwrap();
    assert_eq!(exported, attachment_bytes);

    // Safety-sensitive content fails closed while one newly authorized
    // endpoint has no authenticated session/capability snapshot. Once the
    // account manifest permanently revokes it, fan-out immediately excludes
    // that device and the two live endpoints receive the same content id.
    let (_, mut tablet) = create(&dir, "tablet", &mut rng);
    let tablet_spool = dir.path().join("tablet-spool");
    tablet.add_transport(Arc::new(SneakernetTransport::new(&tablet_spool).unwrap()));
    let tablet_device = tablet.device_id();
    link(
        &mut phone,
        &mut tablet,
        "Tablet",
        DeviceLinkSelection {
            contacts: false,
            organization: false,
            history: false,
        },
        151,
        &mut rng,
    );
    let expanded_manifest = phone.handshake_bundle(160, &mut rng).unwrap();
    carol
        .add_contact(
            "Phone account",
            &expanded_manifest,
            &[DeliveryHint::Spool(phone_spool.clone())],
            160,
            &mut rng,
        )
        .unwrap();

    // Ordinary text retains an honest queued row for the manifest-known
    // tablet before its bundle is available. Importing that exact endpoint's
    // bundle later lets the heartbeat materialize and deliver the pending
    // copy; the placeholder is not a permanent false promise.
    let pending = carol
        .send_message(&account, b"queued until tablet bundle", 161, &mut rng)
        .unwrap();
    carol.tick(162, &mut rng).await.unwrap();
    let pending_deliveries = carol.message_device_deliveries(&pending).unwrap();
    assert_eq!(pending_deliveries.len(), 3);
    assert_eq!(
        pending_deliveries
            .iter()
            .find(|delivery| delivery.device == tablet_device)
            .unwrap()
            .state,
        kult_store::DeliveryState::Queued
    );
    let tablet_bundle = tablet.handshake_bundle(163, &mut rng).unwrap();
    carol
        .add_contact(
            "Phone account",
            &tablet_bundle,
            &[DeliveryHint::Spool(tablet_spool.clone())],
            163,
            &mut rng,
        )
        .unwrap();
    carol.tick(164, &mut rng).await.unwrap();
    assert_eq!(
        carol
            .message_device_deliveries(&pending)
            .unwrap()
            .into_iter()
            .find(|delivery| delivery.device == tablet_device)
            .unwrap()
            .state,
        kult_store::DeliveryState::Sent
    );
    let tablet_events = tablet.tick(165, &mut rng).await.unwrap();
    assert!(tablet_events.iter().any(|event| matches!(
        event,
        Event::MessageReceived { body, .. } if body == b"queued until tablet bundle"
    )));

    assert!(matches!(
        carol.send_disappearing_message(&account, "must reach every device", 3_600, 166, &mut rng),
        Err(NodeError::EphemeralUnsupported)
    ));
    phone
        .revoke_linked_device(&tablet_device, 167, &mut rng)
        .unwrap();
    let revoked_manifest = phone.handshake_bundle(168, &mut rng).unwrap();
    carol
        .add_contact(
            "Phone account",
            &revoked_manifest,
            &[DeliveryHint::Spool(phone_spool.clone())],
            168,
            &mut rng,
        )
        .unwrap();
    let ephemeral = carol
        .send_disappearing_message(&account, "after revocation", 3_600, 169, &mut rng)
        .unwrap();
    carol.tick(170, &mut rng).await.unwrap();
    let phone_events = phone.tick(171, &mut rng).await.unwrap();
    let laptop_events = laptop.tick(171, &mut rng).await.unwrap();
    assert!(phone_events.iter().any(|event| matches!(
        event,
        Event::MessageReceived { body, .. } if body == b"after revocation"
    )));
    assert!(laptop_events.iter().any(|event| matches!(
        event,
        Event::MessageReceived { body, .. } if body == b"after revocation"
    )));
    let deliveries = carol.message_device_deliveries(&ephemeral).unwrap();
    assert_eq!(deliveries.len(), 2);
    assert!(deliveries
        .iter()
        .all(|delivery| delivery.device != tablet_device));

    // One installation's terminal expiry tombstone removes the same
    // received ephemeral row on a partitioned sibling without requiring
    // that sibling's clock sweep to run first.
    assert!(phone
        .messages_with(&carol_id)
        .unwrap()
        .iter()
        .any(|message| message.id == ephemeral));
    assert!(laptop
        .messages_with(&carol_id)
        .unwrap()
        .iter()
        .any(|message| message.id == ephemeral));
    phone.tick(4_000, &mut rng).await.unwrap();
    assert!(!phone
        .messages_with(&carol_id)
        .unwrap()
        .iter()
        .any(|message| message.id == ephemeral));
    let tombstones = phone
        .export_device_sync(&laptop.device_id(), &mut rng)
        .unwrap();
    laptop.import_device_sync(&tombstones, &mut rng).unwrap();
    assert!(!laptop
        .messages_with(&carol_id)
        .unwrap()
        .iter()
        .any(|message| message.id == ephemeral));

    // Replaying a pre-revocation contact manifest is a rollback and must
    // never resurrect the third route, including after process restart.
    carol.mark_verified(&account, &mut rng).unwrap();
    carol
        .rename_contact(&account, "Trusted phone", true, &mut rng)
        .unwrap();
    assert!(matches!(
        carol.add_contact(
            "Phone account",
            &expanded_manifest,
            &[DeliveryHint::Spool(phone_spool.clone())],
            4_001,
            &mut rng,
        ),
        Err(NodeError::InvalidDeviceManifest)
    ));
    let unchanged = carol
        .contacts()
        .unwrap()
        .into_iter()
        .find(|contact| contact.peer == account)
        .unwrap();
    assert_eq!(unchanged.name, "Trusted phone");
    assert!(unchanged.verified);
    drop(carol);
    let mut carol = Node::open(&carol_path, b"pass").unwrap();
    carol.add_transport(Arc::new(SneakernetTransport::new(&carol_spool).unwrap()));
    let after_restart = carol
        .send_disappearing_message(&account, "restart excludes revoked", 3_600, 4_002, &mut rng)
        .unwrap();
    let restart_deliveries = carol.message_device_deliveries(&after_restart).unwrap();
    assert_eq!(restart_deliveries.len(), 2);
    assert!(restart_deliveries
        .iter()
        .all(|delivery| delivery.device != tablet_device));
}
