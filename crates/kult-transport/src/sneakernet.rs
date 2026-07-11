//! The sneakernet transport (docs/05-transports.md §5): sealed envelopes as
//! `.kkb` files in spool directories. The "link" is anything that moves
//! files — USB stick, SD card, shared folder, QR relay.
//!
//! Layout: sends write single-envelope bundles into the peer's spool
//! directory; `recv` drains this node's own inbox directory, deleting files
//! after successful parse. Batching many envelopes into one courier bundle
//! is the delivery engine's job (`kult-node`, M3) — this transport is the
//! minimal faithful carrier.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;

use kult_protocol::{bundle_export, bundle_import, Envelope};

use crate::{
    CostClass, DeliveryHint, LatencyClass, LinkProfile, Reachability, Result, SendReceipt,
    Transport,
};

/// File-drop transport over spool directories.
pub struct SneakernetTransport {
    inbox: PathBuf,
    counter: AtomicU64,
}

impl SneakernetTransport {
    /// Create a transport that receives from `inbox` (created if missing).
    pub fn new(inbox: impl Into<PathBuf>) -> std::io::Result<Self> {
        let inbox = inbox.into();
        std::fs::create_dir_all(&inbox)?;
        Ok(Self {
            inbox,
            counter: AtomicU64::new(0),
        })
    }

    /// This node's inbox directory (hand this path to peers as their
    /// [`DeliveryHint::Spool`] for us).
    pub fn inbox(&self) -> &Path {
        &self.inbox
    }
}

#[async_trait]
impl Transport for SneakernetTransport {
    fn profile(&self) -> LinkProfile {
        LinkProfile {
            // Files impose no frame limit; cap at the bundle envelope cap.
            mtu: 128 * 1024,
            latency: LatencyClass::HumanScale,
            cost: CostClass::Free,
            broadcast: false,
        }
    }

    async fn reachable(&self, peer: &DeliveryHint) -> Reachability {
        match peer {
            DeliveryHint::Spool(dir) if dir.is_dir() => Reachability::StoreAndForward,
            DeliveryHint::Spool(_) => Reachability::Unreachable,
            _ => Reachability::Unreachable,
        }
    }

    async fn send(&self, peer: &DeliveryHint, envelope: &Envelope) -> Result<SendReceipt> {
        let DeliveryHint::Spool(dir) = peer else {
            return Err(crate::TransportError::UnsupportedHint);
        };
        tokio::fs::create_dir_all(dir).await?;
        // Unique, collision-safe name: content id + local counter. Write to
        // a temp name first so readers never observe partial files.
        let seq = self.counter.fetch_add(1, Ordering::Relaxed);
        let id = envelope.content_id();
        let name = format!(
            "{}{:04x}-{seq}.kkb",
            id[0] as u32 * 256 + id[1] as u32,
            id[2] as u32 * 256 + id[3] as u32
        );
        let tmp = dir.join(format!(".{name}.part"));
        let fin = dir.join(name);
        tokio::fs::write(&tmp, bundle_export(std::slice::from_ref(envelope))).await?;
        tokio::fs::rename(&tmp, &fin).await?;
        Ok(SendReceipt::HandedToLink)
    }

    async fn recv(&self) -> Result<Vec<Envelope>> {
        let mut out = Vec::new();
        let mut dir = tokio::fs::read_dir(&self.inbox).await?;
        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            let is_bundle = path.extension().is_some_and(|e| e == "kkb")
                && !path
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with('.'));
            if !is_bundle {
                continue;
            }
            let bytes = tokio::fs::read(&path).await?;
            match bundle_import(&bytes) {
                Ok(envelopes) => {
                    out.extend(envelopes);
                    tokio::fs::remove_file(&path).await?;
                }
                // Corrupt or foreign file: leave it in place for inspection,
                // never loop on it forever — rename it aside.
                Err(_) => {
                    let mut quarantined = path.clone();
                    quarantined.set_extension("kkb.bad");
                    tokio::fs::rename(&path, &quarantined).await?;
                }
            }
        }
        Ok(out)
    }
}
