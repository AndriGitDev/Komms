//! ADR-0015 core acceptance: consent, restart/resume, streamed export, and
//! the hard no-airtime bulk invariant over real node/store/crypto paths.

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rand::rngs::StdRng;
use rand::SeedableRng;

use kult_crypto::KdfProfile;
use kult_node::{AttachmentDirection, AttachmentMetadata, ContentStatus, Event, Node};
use kult_protocol::{Envelope, EnvelopeKind};
use kult_store::MediaTransferState;
use kult_transport::{
    CostClass, DeliveryHint, LatencyClass, LinkProfile, Reachability, SendReceipt, Transport,
    TransportError,
};

const NOW: u64 = 1_800_000_000;
const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

type Net = Arc<Mutex<HashMap<u32, Vec<Envelope>>>>;

struct Link {
    net: Net,
    me: u32,
    cost: CostClass,
    reachable: Arc<AtomicBool>,
    sent: Arc<AtomicUsize>,
}

impl Link {
    fn new(net: &Net, me: u32, cost: CostClass) -> Self {
        Self {
            net: net.clone(),
            me,
            cost,
            reachable: Arc::new(AtomicBool::new(true)),
            sent: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait]
impl Transport for Link {
    fn profile(&self) -> LinkProfile {
        LinkProfile {
            mtu: 64 * 1024,
            latency: if self.cost == CostClass::Airtime {
                LatencyClass::Seconds
            } else {
                LatencyClass::Millis
            },
            cost: self.cost,
            broadcast: false,
        }
    }

    async fn reachable(&self, peer: &DeliveryHint) -> Reachability {
        if self.reachable.load(Ordering::SeqCst) && matches!(peer, DeliveryHint::MeshNode(_)) {
            Reachability::Now
        } else {
            Reachability::Unreachable
        }
    }

    async fn send(
        &self,
        peer: &DeliveryHint,
        envelope: &Envelope,
    ) -> kult_transport::Result<SendReceipt> {
        let DeliveryHint::MeshNode(node) = peer else {
            return Err(TransportError::UnsupportedHint);
        };
        self.sent.fetch_add(1, Ordering::SeqCst);
        self.net
            .lock()
            .unwrap()
            .entry(*node)
            .or_default()
            .push(envelope.clone());
        Ok(SendReceipt::HandedToLink)
    }

    async fn recv(&self) -> kult_transport::Result<Vec<Envelope>> {
        Ok(self
            .net
            .lock()
            .unwrap()
            .entry(self.me)
            .or_default()
            .drain(..)
            .collect())
    }
}

async fn establish(alice: &mut Node, bob: &mut Node, bob_id: [u8; 32], rng: &mut StdRng) {
    alice.send_message(&bob_id, b"hello", NOW, rng).unwrap();
    alice.tick(NOW + 1, rng).await.unwrap();
    bob.tick(NOW + 2, rng).await.unwrap();
    alice.tick(NOW + 3, rng).await.unwrap();
    bob.tick(NOW + 4, rng).await.unwrap();
    alice.tick(NOW + 5, rng).await.unwrap();
}

#[tokio::test]
async fn pairwise_attachment_resumes_after_restart_and_exports_exact_bytes() {
    let mut rng = StdRng::seed_from_u64(0x1501);
    let dir = tempfile::tempdir().unwrap();
    let alice_db = dir.path().join("alice.db");
    let bob_db = dir.path().join("bob.db");
    let net: Net = Arc::new(Mutex::new(HashMap::new()));
    let mut alice = Node::create(&alice_db, b"alice", TEST_KDF, &mut rng).unwrap();
    let mut bob = Node::create(&bob_db, b"bob", TEST_KDF, &mut rng).unwrap();
    alice.add_transport(Arc::new(Link::new(&net, 1, CostClass::Metered)));
    bob.add_transport(Arc::new(Link::new(&net, 2, CostClass::Metered)));

    let alice_bundle = alice.handshake_bundle(NOW, &mut rng).unwrap();
    let bob_bundle = bob.handshake_bundle(NOW, &mut rng).unwrap();
    let bob_id = alice
        .add_contact(
            "bob",
            &bob_bundle,
            &[DeliveryHint::MeshNode(2)],
            NOW,
            &mut rng,
        )
        .unwrap();
    bob.add_contact(
        "alice",
        &alice_bundle,
        &[DeliveryHint::MeshNode(1)],
        NOW,
        &mut rng,
    )
    .unwrap();
    establish(&mut alice, &mut bob, bob_id, &mut rng).await;

    let bytes: Vec<u8> = (0..(kult_crypto::ATTACHMENT_CHUNK_DATA_LEN * 9 + 7))
        .map(|index| (index % 251) as u8)
        .collect();
    let preview = b"bounded locally-generated jpeg preview".to_vec();
    let content_id = alice
        .send_attachment_with_preview(
            &bob_id,
            &AttachmentMetadata {
                media_type: "application/octet-stream".to_owned(),
                filename: Some("restart.bin".to_owned()),
            },
            &mut Cursor::new(&bytes),
            Some((
                &AttachmentMetadata {
                    media_type: "image/jpeg".to_owned(),
                    filename: None,
                },
                &mut Cursor::new(&preview),
            )),
            NOW + 10,
            &mut rng,
        )
        .unwrap();

    alice.tick(NOW + 11, &mut rng).await.unwrap();
    let events = bob.tick(NOW + 12, &mut rng).await.unwrap();
    let transfer_id = events
        .iter()
        .find_map(|event| match event {
            Event::MessageReceived {
                content: ContentStatus::Attachment { id, transfer },
                body,
                ..
            } if *id == content_id && body.is_empty() => Some(*transfer),
            _ => None,
        })
        .expect("supported offer is surfaced without raw manifest bytes");
    let offered = bob
        .attachments()
        .unwrap()
        .into_iter()
        .find(|attachment| attachment.transfer_id == transfer_id)
        .unwrap();
    assert_eq!(offered.direction, AttachmentDirection::Inbound);
    assert_eq!(offered.state, MediaTransferState::AwaitingConsent);
    assert_eq!(offered.objects.len(), 2);
    assert_eq!(offered.objects[0].verified_bytes, 0);
    assert!(offered.objects[1].preview);

    bob.accept_attachment(&transfer_id, NOW + 13, &mut rng)
        .unwrap();
    bob.tick(NOW + 14, &mut rng).await.unwrap();
    alice.tick(NOW + 15, &mut rng).await.unwrap();
    bob.tick(NOW + 16, &mut rng).await.unwrap();
    let partial = bob
        .attachments()
        .unwrap()
        .into_iter()
        .find(|attachment| attachment.transfer_id == transfer_id)
        .unwrap();
    assert_eq!(partial.state, MediaTransferState::Transferring);
    assert_eq!(partial.objects[0].verified_bytes, (8 * 49_152) as u64);

    bob.pause_attachment(&transfer_id, NOW + 17, &mut rng)
        .unwrap();
    bob.tick(NOW + 18, &mut rng).await.unwrap();
    assert_eq!(
        bob.attachments()
            .unwrap()
            .into_iter()
            .find(|attachment| attachment.transfer_id == transfer_id)
            .unwrap()
            .state,
        MediaTransferState::Paused
    );
    bob.resume_attachment(&transfer_id, NOW + 19, &mut rng)
        .unwrap();
    bob.cancel_attachment(&transfer_id, NOW + 20, &mut rng)
        .unwrap();
    bob.tick(NOW + 21, &mut rng).await.unwrap();
    alice.tick(NOW + 22, &mut rng).await.unwrap();
    assert!(alice.attachments().unwrap().iter().any(|attachment| {
        attachment.content_id == content_id && attachment.state == MediaTransferState::Cancelled
    }));
    bob.accept_attachment(&transfer_id, NOW + 23, &mut rng)
        .unwrap();

    drop(bob);
    let mut bob = Node::open(&bob_db, b"bob").unwrap();
    bob.add_transport(Arc::new(Link::new(&net, 2, CostClass::Metered)));
    bob.tick(NOW + 24, &mut rng).await.unwrap();
    alice.tick(NOW + 25, &mut rng).await.unwrap();
    bob.tick(NOW + 26, &mut rng).await.unwrap();

    let idle = NOW + 31 * 86_400;
    bob.tick(idle, &mut rng).await.unwrap();
    assert_eq!(
        bob.attachments()
            .unwrap()
            .into_iter()
            .find(|attachment| attachment.transfer_id == transfer_id)
            .unwrap()
            .state,
        MediaTransferState::Paused,
        "automatic retries stop after 30 days without authenticated progress"
    );
    bob.resume_attachment(&transfer_id, idle + 1, &mut rng)
        .unwrap();
    bob.tick(idle + 2, &mut rng).await.unwrap();
    alice.tick(idle + 3, &mut rng).await.unwrap();
    bob.tick(idle + 4, &mut rng).await.unwrap();

    // Bob's completion acknowledgement is now queued for Alice, but has not
    // been consumed. An explicit local cancellation must remain sticky when
    // that older acknowledgement arrives out of order.
    let outbound_transfer = alice
        .attachments()
        .unwrap()
        .into_iter()
        .find(|attachment| attachment.content_id == content_id)
        .unwrap()
        .transfer_id;
    alice
        .cancel_attachment(&outbound_transfer, idle + 5, &mut rng)
        .unwrap();
    alice.tick(idle + 5, &mut rng).await.unwrap();

    let complete = bob
        .attachments()
        .unwrap()
        .into_iter()
        .find(|attachment| attachment.transfer_id == transfer_id)
        .unwrap();
    assert_eq!(complete.state, MediaTransferState::Complete);
    assert_eq!(complete.objects[0].verified_bytes, bytes.len() as u64);
    assert_eq!(complete.objects[1].verified_bytes, preview.len() as u64);
    let mut exported = Vec::new();
    bob.export_attachment(&transfer_id, &mut exported).unwrap();
    assert_eq!(exported, bytes);
    let mut exported_preview = Vec::new();
    bob.export_attachment_object(&transfer_id, true, &mut exported_preview)
        .unwrap();
    assert_eq!(exported_preview, preview);
    assert!(alice.attachments().unwrap().iter().any(|attachment| {
        attachment.content_id == content_id && attachment.state == MediaTransferState::Cancelled
    }));
}

#[tokio::test]
async fn attachment_offer_emits_no_airtime_frames_when_bulk_route_disappears() {
    let mut rng = StdRng::seed_from_u64(0x1502);
    let dir = tempfile::tempdir().unwrap();
    let net: Net = Arc::new(Mutex::new(HashMap::new()));
    let mut alice = Node::create(&dir.path().join("alice.db"), b"a", TEST_KDF, &mut rng).unwrap();
    let mut bob = Node::create(&dir.path().join("bob.db"), b"b", TEST_KDF, &mut rng).unwrap();
    let alice_fast = Link::new(&net, 1, CostClass::Metered);
    let fast_reachable = alice_fast.reachable.clone();
    let alice_airtime = Link::new(&net, 1, CostClass::Airtime);
    let airtime_sent = alice_airtime.sent.clone();
    alice.add_transport(Arc::new(alice_fast));
    alice.add_transport(Arc::new(alice_airtime));
    bob.add_transport(Arc::new(Link::new(&net, 2, CostClass::Metered)));

    let alice_bundle = alice.handshake_bundle(NOW, &mut rng).unwrap();
    let bob_bundle = bob.handshake_bundle(NOW, &mut rng).unwrap();
    let bob_id = alice
        .add_contact(
            "bob",
            &bob_bundle,
            &[DeliveryHint::MeshNode(2)],
            NOW,
            &mut rng,
        )
        .unwrap();
    bob.add_contact(
        "alice",
        &alice_bundle,
        &[DeliveryHint::MeshNode(1)],
        NOW,
        &mut rng,
    )
    .unwrap();
    establish(&mut alice, &mut bob, bob_id, &mut rng).await;
    let before = airtime_sent.load(Ordering::SeqCst);
    for (media_type, filename, bytes) in [
        (
            "audio/wav",
            "audio-message.wav",
            b"RIFF held canonical audio fixture".as_slice(),
        ),
        (
            "image/png",
            "edited-image.png",
            b"canonical edited image fixture".as_slice(),
        ),
        (
            "application/octet-stream",
            "generic-file.bin",
            b"generic file fixture".as_slice(),
        ),
    ] {
        alice
            .send_attachment(
                &bob_id,
                &AttachmentMetadata {
                    media_type: media_type.to_owned(),
                    filename: Some(filename.to_owned()),
                },
                &mut Cursor::new(bytes),
                NOW + 10,
                &mut rng,
            )
            .unwrap();
    }
    fast_reachable.store(false, Ordering::SeqCst);
    alice.tick(NOW + 11, &mut rng).await.unwrap();
    assert_eq!(
        airtime_sent.load(Ordering::SeqCst),
        before,
        "audio, edited-image, and generic-file manifests and bulk records must emit zero airtime frames"
    );
    assert!(alice.queued().unwrap() == 0, "manifest was never enqueued");
    assert!(net.lock().unwrap().get(&2).is_none_or(Vec::is_empty));
}

#[tokio::test]
async fn group_attachment_encrypts_once_and_members_progress_independently() {
    let mut rng = StdRng::seed_from_u64(0x1503);
    let dir = tempfile::tempdir().unwrap();
    let net: Net = Arc::new(Mutex::new(HashMap::new()));
    let mut nodes = Vec::new();
    for (index, name) in ["a", "b", "c"].iter().enumerate() {
        let mut node = Node::create(
            &dir.path().join(format!("{name}.db")),
            name.as_bytes(),
            TEST_KDF,
            &mut rng,
        )
        .unwrap();
        node.add_transport(Arc::new(Link::new(
            &net,
            index as u32 + 1,
            CostClass::Metered,
        )));
        nodes.push(node);
    }
    let ids: Vec<_> = nodes.iter().map(Node::peer_id).collect();
    let mut bundles = Vec::new();
    for node in &mut nodes {
        bundles.push(vec![
            node.handshake_bundle(NOW, &mut rng).unwrap(),
            node.handshake_bundle(NOW, &mut rng).unwrap(),
        ]);
    }
    for receiver in 0..3 {
        for sender in 0..3 {
            if receiver == sender {
                continue;
            }
            let bundle = &bundles[sender][if receiver < sender {
                receiver
            } else {
                receiver - 1
            }];
            nodes[receiver]
                .add_contact(
                    ["a", "b", "c"][sender],
                    bundle,
                    &[DeliveryHint::MeshNode(sender as u32 + 1)],
                    NOW,
                    &mut rng,
                )
                .unwrap();
        }
    }
    let mut iter = nodes.into_iter();
    let mut alice = iter.next().unwrap();
    let mut bob = iter.next().unwrap();
    let mut carol = iter.next().unwrap();
    let group = alice
        .create_group("attachments", &[ids[1], ids[2]], &mut rng)
        .unwrap();
    alice
        .group_send(&group, b"session warmup", NOW, &mut rng)
        .unwrap();
    alice.tick(NOW + 1, &mut rng).await.unwrap();
    bob.tick(NOW + 5, &mut rng).await.unwrap();
    carol.tick(NOW + 5, &mut rng).await.unwrap();
    alice.tick(NOW + 10, &mut rng).await.unwrap();
    bob.tick(NOW + 11, &mut rng).await.unwrap();
    carol.tick(NOW + 11, &mut rng).await.unwrap();
    alice.tick(NOW + 12, &mut rng).await.unwrap();

    let bytes = vec![0x5a; kult_crypto::ATTACHMENT_CHUNK_DATA_LEN + 1];
    let preview = b"group jpeg preview".to_vec();
    let content_id = alice
        .send_group_attachment_with_preview(
            &group,
            &AttachmentMetadata {
                media_type: "image/png".to_owned(),
                filename: Some("group.png".to_owned()),
            },
            &mut Cursor::new(&bytes),
            Some((
                &AttachmentMetadata {
                    media_type: "image/jpeg".to_owned(),
                    filename: None,
                },
                &mut Cursor::new(&preview),
            )),
            NOW + 20,
            &mut rng,
        )
        .unwrap();
    alice.tick(NOW + 21, &mut rng).await.unwrap();
    {
        let network = net.lock().unwrap();
        let copies: Vec<_> = [2u32, 3]
            .into_iter()
            .flat_map(|recipient| network.get(&recipient).into_iter().flatten())
            .filter(|envelope| envelope.kind == EnvelopeKind::GroupMessage)
            .map(|envelope| envelope.body.clone())
            .collect();
        assert_eq!(copies.len(), 2);
        assert_eq!(
            copies[0], copies[1],
            "manifest is sender-key encrypted once"
        );
    }
    let bob_events = bob.tick(NOW + 22, &mut rng).await.unwrap();
    let carol_events = carol.tick(NOW + 22, &mut rng).await.unwrap();
    let offered = |events: &[Event]| {
        events.iter().find_map(|event| match event {
            Event::GroupMessageReceived {
                content: ContentStatus::Attachment { id, transfer },
                body,
                ..
            } if *id == content_id && body.is_empty() => Some(*transfer),
            _ => None,
        })
    };
    let bob_transfer = offered(&bob_events).unwrap();
    let carol_transfer = offered(&carol_events).unwrap();

    bob.accept_attachment(&bob_transfer, NOW + 23, &mut rng)
        .unwrap();
    carol
        .reject_attachment(&carol_transfer, NOW + 23, &mut rng)
        .unwrap();
    bob.tick(NOW + 24, &mut rng).await.unwrap();
    carol.tick(NOW + 24, &mut rng).await.unwrap();
    alice.tick(NOW + 25, &mut rng).await.unwrap();
    bob.tick(NOW + 26, &mut rng).await.unwrap();
    alice.tick(NOW + 27, &mut rng).await.unwrap();
    assert_eq!(
        bob.attachments()
            .unwrap()
            .into_iter()
            .find(|attachment| attachment.transfer_id == bob_transfer)
            .unwrap()
            .state,
        MediaTransferState::Complete
    );
    assert_eq!(
        carol
            .attachments()
            .unwrap()
            .into_iter()
            .find(|attachment| attachment.transfer_id == carol_transfer)
            .unwrap()
            .state,
        MediaTransferState::Rejected
    );
    let outbound = alice.attachments().unwrap();
    assert!(outbound.iter().any(|attachment| {
        attachment.peer == ids[1] && attachment.state == MediaTransferState::Complete
    }));
    assert!(outbound.iter().any(|attachment| {
        attachment.peer == ids[2] && attachment.state == MediaTransferState::Rejected
    }));
    assert_eq!(
        std::fs::read_dir(dir.path().join("a.db.media"))
            .unwrap()
            .count(),
        3,
        "two entitled members reuse one sealed chunk set per object"
    );

    carol
        .accept_attachment(&carol_transfer, NOW + 28, &mut rng)
        .unwrap();
    carol.tick(NOW + 29, &mut rng).await.unwrap();
    alice.tick(NOW + 30, &mut rng).await.unwrap();
    carol.tick(NOW + 31, &mut rng).await.unwrap();
    alice.tick(NOW + 32, &mut rng).await.unwrap();
    let mut exported = Vec::new();
    carol
        .export_attachment(&carol_transfer, &mut exported)
        .unwrap();
    assert_eq!(exported, bytes);
    let mut exported_preview = Vec::new();
    carol
        .export_attachment_object(&carol_transfer, true, &mut exported_preview)
        .unwrap();
    assert_eq!(exported_preview, preview);
}
