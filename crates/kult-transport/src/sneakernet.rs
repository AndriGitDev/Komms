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
use tokio::io::AsyncReadExt;

use kult_protocol::{bundle_export, bundle_import, Envelope, MAX_BUNDLE_BYTES, MAX_ENVELOPE_BYTES};

use crate::{
    CostClass, DeliveryHint, LatencyClass, LinkProfile, Reachability, Result, SendReceipt,
    Transport,
};

/// File-drop transport over spool directories.
pub struct SneakernetTransport {
    inbox: PathBuf,
    counter: AtomicU64,
}

/// Bound directory work and aggregate allocation for one receive pass.
const MAX_FILES_PER_RECV: usize = 256;
const MAX_DIRECTORY_ENTRIES_PER_RECV: usize = 1_024;
const MAX_BYTES_PER_RECV: usize = MAX_BUNDLE_BYTES;

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

    async fn quarantine(&self, path: &Path) -> std::io::Result<PathBuf> {
        for attempt in 0..64u64 {
            let candidate = if attempt == 0 {
                let mut candidate = path.to_path_buf();
                candidate.set_extension("kkb.bad");
                candidate
            } else {
                let sequence = self.counter.fetch_add(1, Ordering::Relaxed);
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                self.inbox.join(format!("{name}.{sequence}.bad"))
            };
            match tokio::fs::symlink_metadata(&candidate).await {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    tokio::fs::rename(path, &candidate).await?;
                    return Ok(candidate);
                }
                Ok(_) => continue,
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a unique quarantine name",
        ))
    }
}

#[async_trait]
impl Transport for SneakernetTransport {
    fn profile(&self) -> LinkProfile {
        LinkProfile {
            // Files impose no frame limit; cap at the bundle envelope cap.
            mtu: MAX_ENVELOPE_BYTES,
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
        // Validate and serialize before touching the destination filesystem:
        // an oversized envelope is a typed protocol refusal, never a partial
        // or empty courier artifact.
        let bundle = bundle_export(std::slice::from_ref(envelope))?;
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
        tokio::fs::write(&tmp, bundle).await?;
        tokio::fs::rename(&tmp, &fin).await?;
        Ok(SendReceipt::HandedToLink)
    }

    async fn recv(&self) -> Result<Vec<Envelope>> {
        let mut out = Vec::new();
        let mut entries_examined = 0usize;
        let mut files_examined = 0usize;
        let mut bytes_admitted = 0usize;
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
            if entries_examined >= MAX_DIRECTORY_ENTRIES_PER_RECV {
                break;
            }
            entries_examined += 1;

            let file_type = entry.file_type().await?;
            if !file_type.is_file() {
                // A persistent directory or symlink with a bundle suffix
                // must not consume every future file budget. Move the entry
                // out of the candidate namespace without following it.
                self.quarantine(&path).await?;
                continue;
            }
            if files_examined >= MAX_FILES_PER_RECV {
                break;
            }
            files_examined += 1;

            let metadata = entry.metadata().await?;
            let file_len = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
            if file_len > MAX_BUNDLE_BYTES {
                self.quarantine(&path).await?;
                continue;
            }
            let remaining = MAX_BYTES_PER_RECV.saturating_sub(bytes_admitted);
            if file_len > remaining {
                break;
            }

            // Read through a hard ceiling even if another process grows the
            // file after metadata inspection.
            let mut file = tokio::fs::File::open(&path).await?;
            let mut bytes = Vec::with_capacity(file_len);
            (&mut file)
                .take((remaining + 1) as u64)
                .read_to_end(&mut bytes)
                .await?;
            if bytes.len() > remaining {
                break;
            }
            bytes_admitted += bytes.len();
            match bundle_import(&bytes) {
                Ok(envelopes) => {
                    out.extend(envelopes);
                    tokio::fs::remove_file(&path).await?;
                }
                // Corrupt or foreign file: leave it in place for inspection,
                // never loop on it forever — rename it aside.
                Err(_) => {
                    self.quarantine(&path).await?;
                }
            }
        }
        Ok(out)
    }
}
