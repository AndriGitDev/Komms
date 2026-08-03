//! Initial linked-device transfer keeps only durable, accurately described
//! history and terminal expiry tombstones.

use kult_crypto::{DeviceAuthorityManifest, Identity, KdfProfile};
use kult_store::{
    DeliveryState, DeviceAuthorityStateRecord, DeviceTransferSelection, Direction,
    DiscoveryCapabilityState, EphemeralConversation, EphemeralMode, EphemeralRecord,
    EphemeralState, GroupDelivery, GroupMessageRecord, GroupOriginAuthentication, MessageRecord,
    Store,
};
use rand::{rngs::StdRng, SeedableRng};

const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

#[test]
fn transfer_excludes_legacy_and_active_ephemeral_history_and_clears_wire_state() {
    let mut rng = StdRng::seed_from_u64(0xd3_71ce);
    let directory = tempfile::tempdir().unwrap();
    let root = Identity::generate(&mut rng);
    let device = Identity::generate(&mut rng);
    let manifest =
        DeviceAuthorityManifest::initial(&root, &device, "This device".into(), 0, &mut rng)
            .unwrap();
    let authority = DeviceAuthorityStateRecord {
        local_device_secret: device.to_bytes().to_vec(),
        local_certificate: manifest.devices()[0].certificate.clone(),
        accepted_recovery_epoch: manifest.recovery_epoch(),
        accepted_recovery_anchor: manifest.recovery_anchor_id(),
        manifest,
        sync_counter: 0,
        channels: Vec::new(),
        conflicts: Vec::new(),
        discovery: DiscoveryCapabilityState {
            capability: [0xa1; 32],
            generation: 1,
            legacy_v1_enabled: false,
        },
    };
    let store = Store::create_authority_profile(
        &directory.path().join("device-transfer.db"),
        b"passphrase",
        TEST_KDF,
        &root.public(),
        &authority,
        b"test-prekeys",
        &mut rng,
    )
    .unwrap();

    let peer = [0x11; 32];
    let group = [0x22; 32];
    let me = [0x33; 32];
    let active_pairwise_id = [0x41; 16];
    let ordinary_pairwise_id = [0x42; 16];
    let legacy_group_id = [0x51; 16];
    let active_group_id = [0x52; 16];
    let authenticated_group_id = [0x53; 16];

    for record in [
        MessageRecord {
            id: active_pairwise_id,
            peer,
            direction: Direction::Inbound,
            state: DeliveryState::Delivered,
            timestamp: 1,
            body: b"active ephemeral pairwise plaintext".to_vec(),
            wire_id: None,
        },
        MessageRecord {
            id: ordinary_pairwise_id,
            peer,
            direction: Direction::Outbound,
            state: DeliveryState::Sent,
            timestamp: 2,
            body: b"ordinary pairwise history".to_vec(),
            wire_id: Some([0x61; 16]),
        },
    ] {
        store.put_message(&record, &mut rng).unwrap();
    }

    for record in [
        GroupMessageRecord {
            id: legacy_group_id,
            group,
            sender: peer,
            direction: Direction::Inbound,
            timestamp: 3,
            body: b"legacy membership-authenticated history".to_vec(),
            deliveries: Vec::new(),
            wire_body: None,
            origin: GroupOriginAuthentication::LegacyMembership,
        },
        GroupMessageRecord {
            id: active_group_id,
            group,
            sender: peer,
            direction: Direction::Inbound,
            timestamp: 4,
            body: b"active ephemeral group plaintext".to_vec(),
            deliveries: Vec::new(),
            wire_body: None,
            origin: GroupOriginAuthentication::RecipientV1 {
                sender_device: [0x71; 32],
                recipient_device: [0x72; 32],
                chain_key_id: [0x73; 16],
            },
        },
        GroupMessageRecord {
            id: authenticated_group_id,
            group,
            sender: me,
            direction: Direction::Outbound,
            timestamp: 5,
            body: b"recipient-authenticated group history".to_vec(),
            deliveries: vec![GroupDelivery {
                peer,
                wire_id: Some([0x81; 16]),
                state: DeliveryState::Queued,
            }],
            wire_body: Some(b"live pending fanout".to_vec()),
            origin: GroupOriginAuthentication::OutboundV1 {
                sender_device: [0x82; 32],
                chain_key_id: [0x83; 16],
            },
        },
    ] {
        store.put_group_message(&record, &mut rng).unwrap();
    }

    for record in [
        EphemeralRecord {
            conversation: EphemeralConversation::Pairwise(peer),
            author: peer,
            content_id: active_pairwise_id,
            expires_at: 100,
            mode: EphemeralMode::DisappearingText,
            state: EphemeralState::Active,
            transfer_ids: Vec::new(),
        },
        EphemeralRecord {
            conversation: EphemeralConversation::Group(group),
            author: peer,
            content_id: active_group_id,
            expires_at: 101,
            mode: EphemeralMode::DisappearingText,
            state: EphemeralState::Active,
            transfer_ids: Vec::new(),
        },
        EphemeralRecord {
            conversation: EphemeralConversation::Pairwise(peer),
            author: me,
            content_id: [0x91; 16],
            expires_at: 99,
            mode: EphemeralMode::ViewOnceAttachment,
            state: EphemeralState::Expired,
            transfer_ids: vec![[0x92; 16]],
        },
    ] {
        store.put_ephemeral_record(&record, &mut rng).unwrap();
    }

    let transfer = store
        .export_device_transfer(DeviceTransferSelection::default())
        .unwrap();
    assert_eq!(transfer.discovery, authority.discovery);

    assert_eq!(transfer.messages.len(), 1);
    assert_eq!(transfer.messages[0].id, ordinary_pairwise_id);
    assert_eq!(transfer.messages[0].state, DeliveryState::Failed);
    assert_eq!(transfer.messages[0].wire_id, None);

    assert_eq!(transfer.group_messages.len(), 1);
    let group_message = &transfer.group_messages[0];
    assert_eq!(group_message.id, authenticated_group_id);
    assert_eq!(group_message.wire_body, None);
    assert_eq!(group_message.deliveries.len(), 1);
    assert_eq!(group_message.deliveries[0].wire_id, None);
    assert_eq!(group_message.deliveries[0].state, DeliveryState::Failed);

    assert_eq!(transfer.ephemeral_tombstones.len(), 1);
    assert_eq!(
        transfer.ephemeral_tombstones[0].state,
        EphemeralState::Expired
    );
    assert!(transfer.ephemeral_tombstones[0].transfer_ids.is_empty());
}
