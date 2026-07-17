//! B13 acceptance: private icons are canonical, sealed, portable, local-only,
//! and safely fall back when absent or malformed.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use image::codecs::png::PngEncoder;
use image::{ImageEncoder, Rgba, RgbaImage};
use rand::{rngs::StdRng, SeedableRng};

use kult_crypto::KdfProfile;
use kult_node::{
    CustomIconCrop, CustomIconTarget, Event, Node, NodeError, CUSTOM_ICON_BUNDLED_GLYPHS,
    CUSTOM_ICON_DIMENSION, CUSTOM_ICON_MEDIA_TYPE,
};
use kult_protocol::Envelope;
use kult_store::{CustomIconRecord, LocalMetadataRecord, Store};
use kult_transport::{
    CostClass, DeliveryHint, LatencyClass, LinkProfile, Reachability, SendReceipt, Transport,
};

const NOW: u64 = 1_800_000_000;
const TEST_KDF: KdfProfile = KdfProfile {
    m_cost_kib: 8,
    t_cost: 1,
    p_cost: 1,
};

#[derive(Default)]
struct SpyTransport {
    sends: AtomicUsize,
    reachability: AtomicUsize,
}

#[async_trait]
impl Transport for SpyTransport {
    fn profile(&self) -> LinkProfile {
        LinkProfile {
            mtu: 64 * 1024,
            latency: LatencyClass::Millis,
            cost: CostClass::Free,
            broadcast: false,
        }
    }

    async fn reachable(&self, _peer: &DeliveryHint) -> Reachability {
        self.reachability.fetch_add(1, Ordering::SeqCst);
        Reachability::Now
    }

    async fn send(
        &self,
        _peer: &DeliveryHint,
        _envelope: &Envelope,
    ) -> kult_transport::Result<SendReceipt> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        Ok(SendReceipt::HandedToLink)
    }

    async fn recv(&self) -> kult_transport::Result<Vec<Envelope>> {
        Ok(Vec::new())
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

fn source_with_private_metadata(path: &std::path::Path) {
    let pixels = RgbaImage::from_fn(320, 240, |x, y| {
        Rgba([(x % 251) as u8, (y % 241) as u8, ((x + y) % 239) as u8, 255])
    });
    let mut png = Vec::new();
    PngEncoder::new(&mut png)
        .write_image(
            pixels.as_raw(),
            pixels.width(),
            pixels.height(),
            image::ExtendedColorType::Rgba8,
        )
        .unwrap();
    let iend = png
        .windows(4)
        .rposition(|window| window == b"IEND")
        .unwrap()
        - 4;
    let data = b"Comment\0GPS: secret place";
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&(data.len() as u32).to_be_bytes());
    chunk.extend_from_slice(b"tEXt");
    chunk.extend_from_slice(data);
    let mut crc_input = b"tEXt".to_vec();
    crc_input.extend_from_slice(data);
    chunk.extend_from_slice(&crc32(&crc_input).to_be_bytes());
    png.splice(iend..iend, chunk);
    std::fs::write(path, png).unwrap();
}

#[test]
fn every_target_source_restart_restore_fallback_and_zero_network_work() {
    let mut rng = StdRng::seed_from_u64(0xb13);
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("node.db");
    let mut node = Node::create(&database, b"pass", TEST_KDF, &mut rng).unwrap();
    let mut peer_node = Node::create(
        &directory.path().join("peer.db"),
        b"peer",
        TEST_KDF,
        &mut rng,
    )
    .unwrap();
    let bundle = peer_node.handshake_bundle(NOW, &mut rng).unwrap();
    let peer = node
        .add_contact("Duplicate name", &bundle, &[], NOW, &mut rng)
        .unwrap();
    let group = node
        .create_group("Duplicate name", &[peer], &mut rng)
        .unwrap();
    let folder = node.create_folder("Duplicate name", &mut rng).unwrap();
    node.drain_events();

    let spy = Arc::new(SpyTransport::default());
    node.add_transport(spy.clone());
    let queue_before = node.queued().unwrap();

    let source = directory.path().join("camera.png");
    source_with_private_metadata(&source);
    let contact = CustomIconTarget::Contact(peer);
    let contact_icon = node
        .set_custom_icon_from_path(
            contact.clone(),
            &source,
            Some(CustomIconCrop {
                x: 40,
                y: 0,
                width: 240,
                height: 240,
            }),
            &mut rng,
        )
        .unwrap();
    assert_eq!(
        (contact_icon.width, contact_icon.height),
        (CUSTOM_ICON_DIMENSION, CUSTOM_ICON_DIMENSION)
    );
    assert_eq!(contact_icon.media_type, CUSTOM_ICON_MEDIA_TYPE);
    for private in [b"Comment".as_slice(), b"GPS", b"secret place", b"tEXt"] {
        assert!(!contact_icon
            .bytes
            .windows(private.len())
            .any(|window| window == private));
    }

    let targets = [
        CustomIconTarget::Group(group),
        CustomIconTarget::Folder(folder.id),
        CustomIconTarget::NoteToSelf,
    ];
    for (target, glyph) in targets.iter().zip(CUSTOM_ICON_BUNDLED_GLYPHS) {
        node.set_bundled_custom_icon(target.clone(), glyph, &mut rng)
            .unwrap();
    }
    assert_eq!(node.custom_icon_usage().unwrap().records, 4);
    assert_eq!(node.drain_events().len(), 4);

    node.set_bundled_custom_icon(targets[0].clone(), "compass", &mut rng)
        .unwrap();
    assert_eq!(node.drain_events(), vec![Event::CustomIconsChanged]);
    node.set_bundled_custom_icon(targets[0].clone(), "compass", &mut rng)
        .unwrap();
    assert!(node.drain_events().is_empty());
    assert!(matches!(
        node.set_bundled_custom_icon(targets[0].clone(), "remote-url", &mut rng),
        Err(NodeError::InvalidCustomIcon)
    ));
    assert!(matches!(
        node.set_custom_icon_from_path(
            contact.clone(),
            &source,
            Some(CustomIconCrop {
                x: 0,
                y: 0,
                width: 100,
                height: 99,
            }),
            &mut rng,
        ),
        Err(NodeError::InvalidCustomIcon)
    ));
    assert!(matches!(
        node.set_bundled_custom_icon(CustomIconTarget::Contact([0xff; 32]), "person", &mut rng),
        Err(NodeError::UnavailableCustomIconTarget)
    ));
    assert_eq!(node.queued().unwrap(), queue_before);
    assert_eq!(spy.sends.load(Ordering::SeqCst), 0);
    assert_eq!(spy.reachability.load(Ordering::SeqCst), 0);

    drop(node);
    let mut reopened = Node::open(&database, b"pass").unwrap();
    assert_eq!(
        reopened.custom_icon(&contact).unwrap().unwrap().bytes,
        contact_icon.bytes
    );
    assert!(reopened.clear_custom_icon(&targets[2]).unwrap());
    assert!(!reopened.clear_custom_icon(&targets[2]).unwrap());
    assert!(reopened.custom_icon(&targets[2]).unwrap().is_none());

    let (backup, mnemonic) = reopened.export_backup(NOW, &mut rng).unwrap();
    assert_eq!(&backup[..4], b"KKR7");
    let restored = Node::restore(
        &directory.path().join("restored.db"),
        &backup,
        &mnemonic,
        b"restored",
        TEST_KDF,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        restored.custom_icon(&contact).unwrap().unwrap().bytes,
        contact_icon.bytes
    );
    drop(restored);

    drop(reopened);
    let store = Store::open(&database, b"pass").unwrap();
    store
        .put_local_metadata(
            &LocalMetadataRecord::CustomIcon(CustomIconRecord {
                target: contact.clone(),
                media_type: CUSTOM_ICON_MEDIA_TYPE.to_owned(),
                bytes: b"corrupt but sealed legacy bytes".to_vec(),
            }),
            &mut rng,
        )
        .unwrap();
    drop(store);
    let reopened = Node::open(&database, b"pass").unwrap();
    assert!(reopened.custom_icon(&contact).unwrap().is_none());
}
