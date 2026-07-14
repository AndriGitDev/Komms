//! Sealed attachment metadata and crash-safe media chunk files (ADR-0015).

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use rand_core::CryptoRngCore;
use rusqlite::{params, OptionalExtension};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use kult_crypto::bulk_hash;
use kult_protocol::{
    attachment_chunk_count, ATTACHMENT_SEALED_CHUNK_LEN, MAX_ATTACHMENT_FILENAME_LEN,
    MAX_ATTACHMENT_MEDIA_TYPE_LEN, MAX_PREVIEW_CHUNKS, MAX_PREVIEW_OBJECT_LEN, MAX_PRIMARY_CHUNKS,
    MAX_PRIMARY_OBJECT_LEN,
};

use crate::{Result, Store, StoreError};

const MEDIA_RECORD_VERSION: u8 = 1;
const MEDIA_TRANSFER_AD: &[u8] = b"media-transfer";
const MEDIA_OBJECT_AD: &[u8] = b"media-object";
const MEDIA_CHUNK_AD: &[u8] = b"KAT-store-chunk-v1";
const MAX_ENTITLEMENTS: usize = 64;
const LOCAL_SEAL_OVERHEAD: u64 = 24 + 16;

/// Default media-store quota (2 GiB).
pub const DEFAULT_MEDIA_STORE_QUOTA: u64 = 2 * 1024 * 1024 * 1024;
/// Protocol-hard configurable media-store ceiling (64 GiB).
pub const MAX_MEDIA_STORE_QUOTA: u64 = 64 * 1024 * 1024 * 1024;
/// Default maximum bytes occupied by incomplete sealed chunks (1 GiB).
pub const DEFAULT_INCOMPLETE_MEDIA_LIMIT: u64 = 1024 * 1024 * 1024;
/// Default filesystem free-space reserve (256 MiB).
pub const DEFAULT_MEDIA_FREE_SPACE_RESERVE: u64 = 256 * 1024 * 1024;

/// Pairwise or group scope for sealed transfer metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MediaScope {
    /// Two-party conversation.
    Pairwise,
    /// Sender-key group conversation.
    Group,
}

/// Local direction of an attachment transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MediaDirection {
    /// Bytes are being received from the manifest author.
    Inbound,
    /// This device authored and may serve the object.
    Outbound,
}

/// Durable attachment lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MediaTransferState {
    /// Valid manifest retained in history; no consent decision yet.
    Offered,
    /// Waiting for explicit local consent.
    AwaitingConsent,
    /// Accepted and ready for an eligible carrier.
    Queued,
    /// At least one verified chunk has been committed.
    Transferring,
    /// Explicitly paused while progress remains durable.
    Paused,
    /// Every chunk and the final object hash were verified.
    Complete,
    /// Durable receiver refusal.
    Rejected,
    /// Transfer activity was cancelled.
    Cancelled,
    /// Authentication or final object integrity failed.
    Corrupt,
    /// Manifest exists but required local media state or files do not.
    Unavailable,
}

impl MediaTransferState {
    fn active(self) -> bool {
        matches!(self, Self::Queued | Self::Transferring | Self::Paused)
    }

    fn incomplete(self) -> bool {
        !matches!(
            self,
            Self::Complete | Self::Rejected | Self::Cancelled | Self::Corrupt
        )
    }
}

/// Configurable store limits, bounded by ADR-0015 hard ceilings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MediaLimits {
    /// Active inbound objects permitted for one peer.
    pub active_inbound_per_peer: usize,
    /// Active outbound objects permitted for one peer.
    pub active_outbound_per_peer: usize,
    /// Active objects permitted across the whole store.
    pub active_global: usize,
    /// Maximum bytes of incomplete locally sealed chunks.
    pub incomplete_bytes: u64,
    /// Configured media directory quota.
    pub store_bytes: u64,
    /// Free filesystem bytes retained after a commit.
    pub free_space_reserve: u64,
}

impl Default for MediaLimits {
    fn default() -> Self {
        Self {
            active_inbound_per_peer: 8,
            active_outbound_per_peer: 8,
            active_global: 32,
            incomplete_bytes: DEFAULT_INCOMPLETE_MEDIA_LIMIT,
            store_bytes: DEFAULT_MEDIA_STORE_QUOTA,
            free_space_reserve: DEFAULT_MEDIA_FREE_SPACE_RESERVE,
        }
    }
}

impl MediaLimits {
    fn validate(self) -> Result<Self> {
        if self.active_inbound_per_peer > 8
            || self.active_outbound_per_peer > 8
            || self.active_global > 32
            || self.incomplete_bytes > DEFAULT_INCOMPLETE_MEDIA_LIMIT
            || self.store_bytes > MAX_MEDIA_STORE_QUOTA
            || self.store_bytes == 0
        {
            return Err(StoreError::MediaQuota);
        }
        Ok(self)
    }
}

/// Sealed transfer-level metadata and original entitlement snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaTransferRecord {
    /// Random local row id, unrelated to protocol ids.
    pub local_id: [u8; 16],
    /// Pairwise peer or original manifest author for inbound group transfers.
    pub peer: [u8; 32],
    /// Inbound or outbound transfer direction.
    pub direction: MediaDirection,
    /// Conversation scope.
    pub scope: MediaScope,
    /// Pairwise conversation hash or group id.
    pub scope_id: [u8; 32],
    /// Original manifest author.
    pub manifest_author: [u8; 32],
    /// ADR-0014 Attachment content id.
    pub manifest_content_id: [u8; 16],
    /// Durable group members entitled when the manifest was sent.
    pub entitled_peers: Vec<[u8; 32]>,
    /// Transfer lifecycle state.
    pub state: MediaTransferState,
    /// Last authenticated progress time in Unix seconds.
    pub updated_at: u64,
}

/// Sealed object-level metadata, progress bitmap, and chunk-address map.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaObjectRecord {
    /// Random local row id, unrelated to protocol ids.
    pub local_id: [u8; 16],
    /// Random local transfer row id.
    pub transfer_id: [u8; 16],
    /// Random object id from the manifest.
    pub object_id: [u8; 16],
    /// Zero for primary or one for preview.
    pub role: u8,
    /// Exact unpadded object size.
    pub total_len: u64,
    /// Exact manifest-derived chunk count.
    pub chunk_count: u32,
    /// BLAKE3 of the exact unpadded object.
    pub content_hash: [u8; 32],
    /// Authenticated media-type display hint.
    pub media_type: String,
    /// Optional sanitized filename display hint.
    pub filename: Option<String>,
    /// Object lifecycle state.
    pub state: MediaTransferState,
    /// One bit per durably committed chunk.
    pub verified_bitmap: Vec<u8>,
    /// Sealed mapping from index to ciphertext-derived local address.
    pub chunk_addresses: Vec<Option<[u8; 32]>>,
    /// Manifest-derived byte progress for committed chunks.
    pub verified_bytes: u64,
}

/// Result of reading a versioned sealed media metadata row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MediaRecord<T> {
    /// Record version is supported and fully decoded.
    Available(T),
    /// Unknown version was quarantined without partial decoding.
    Unavailable {
        /// Random local row id.
        local_id: [u8; 16],
        /// Unknown record version byte.
        version: u8,
    },
}

/// Aggregate media-store usage and active-object counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MediaUsage {
    /// Bytes occupied by unique locally sealed chunk files.
    pub sealed_file_bytes: u64,
    /// Referenced bytes belonging to incomplete objects.
    pub incomplete_bytes: u64,
    /// Active object count across the store.
    pub active_objects: usize,
}

/// Work performed by startup media reconciliation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MediaReconciliation {
    /// Stale same-directory temporary files removed.
    pub stale_temps_removed: usize,
    /// Unreferenced final chunk files removed.
    pub orphan_files_removed: usize,
    /// Objects moved to `Unavailable` because referenced files were absent.
    pub missing_objects: usize,
    /// Unknown record versions conservatively quarantined.
    pub unknown_records: usize,
}

pub(crate) fn prepare_media_directory(store_path: &Path) -> Result<PathBuf> {
    let name = store_path.file_name().ok_or(StoreError::NotAStore)?;
    let mut media_name = OsString::from(name);
    media_name.push(".media");
    let media_dir = store_path.with_file_name(media_name);
    fs::create_dir_all(&media_dir)?;
    set_private_directory_permissions(&media_dir)?;
    remove_stale_temps(&media_dir)?;
    Ok(media_dir)
}

impl Store {
    /// Replace runtime media limits, never exceeding ADR-0015 hard ceilings.
    pub fn set_media_limits(&mut self, limits: MediaLimits) -> Result<()> {
        self.media_limits = limits.validate()?;
        Ok(())
    }

    /// Current runtime media limits.
    pub fn media_limits(&self) -> MediaLimits {
        self.media_limits
    }

    /// Insert or replace one sealed transfer metadata record.
    pub fn put_media_transfer(
        &self,
        record: &MediaTransferRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        validate_transfer(record)?;
        let sealed = seal_record(&self.k_media, MEDIA_TRANSFER_AD, record, rng)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO media_transfers (id, blob) VALUES (?1, ?2)",
            params![record.local_id.as_slice(), sealed],
        )?;
        Ok(())
    }

    /// Read one transfer row, quarantining unknown versions.
    pub fn get_media_transfer(
        &self,
        local_id: &[u8; 16],
    ) -> Result<Option<MediaRecord<MediaTransferRecord>>> {
        self.get_media_record("media_transfers", MEDIA_TRANSFER_AD, local_id)
    }

    /// Read every transfer metadata row.
    pub fn media_transfers(&self) -> Result<Vec<MediaRecord<MediaTransferRecord>>> {
        self.media_records("media_transfers", MEDIA_TRANSFER_AD)
    }

    /// Transition transfer-level lifecycle state and authenticated progress
    /// time while retaining its sealed entitlement snapshot.
    pub fn set_media_transfer_state(
        &self,
        local_id: &[u8; 16],
        state: MediaTransferState,
        updated_at: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let mut transfer = self.require_transfer(local_id)?;
        transfer.state = state;
        transfer.updated_at = updated_at;
        self.put_media_transfer(&transfer, rng)
    }

    /// Delete one transfer row after its object rows have been removed.
    pub fn delete_media_transfer(&self, local_id: &[u8; 16]) -> Result<()> {
        if self.media_objects()?.into_iter().any(
            |record| matches!(record, MediaRecord::Available(object) if object.transfer_id == *local_id),
        ) {
            return Err(StoreError::MediaState);
        }
        self.conn.execute(
            "DELETE FROM media_transfers WHERE id = ?1",
            params![local_id.as_slice()],
        )?;
        Ok(())
    }

    /// Insert or replace one sealed object record after enforcing bounds.
    pub fn put_media_object(
        &self,
        record: &MediaObjectRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        validate_object(record)?;
        let transfer = self.require_transfer(&record.transfer_id)?;
        if record.state.active() {
            self.enforce_active_limits(&transfer, Some(record.local_id))?;
        }
        let sealed = seal_record(&self.k_media, MEDIA_OBJECT_AD, record, rng)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO media_objects (id, blob) VALUES (?1, ?2)",
            params![record.local_id.as_slice(), sealed],
        )?;
        Ok(())
    }

    /// Read one object row, quarantining unknown versions.
    pub fn get_media_object(
        &self,
        local_id: &[u8; 16],
    ) -> Result<Option<MediaRecord<MediaObjectRecord>>> {
        self.get_media_record("media_objects", MEDIA_OBJECT_AD, local_id)
    }

    /// Read every object metadata row.
    pub fn media_objects(&self) -> Result<Vec<MediaRecord<MediaObjectRecord>>> {
        self.media_records("media_objects", MEDIA_OBJECT_AD)
    }

    /// Read supported object rows belonging to one transfer, preserving
    /// manifest role order.
    pub fn media_objects_for_transfer(
        &self,
        transfer_id: &[u8; 16],
    ) -> Result<Vec<MediaObjectRecord>> {
        let mut objects: Vec<_> = self
            .media_objects()?
            .into_iter()
            .filter_map(|record| match record {
                MediaRecord::Available(object) if object.transfer_id == *transfer_id => {
                    Some(object)
                }
                _ => None,
            })
            .collect();
        objects.sort_by_key(|object| object.role);
        Ok(objects)
    }

    /// Transition an object state while retaining sealed progress metadata.
    pub fn set_media_object_state(
        &self,
        local_id: &[u8; 16],
        state: MediaTransferState,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let mut object = self.require_object(local_id)?;
        if state.active() && !object.state.active() {
            let transfer = self.require_transfer(&object.transfer_id)?;
            self.enforce_active_limits(&transfer, Some(object.local_id))?;
        }
        object.state = state;
        if matches!(
            state,
            MediaTransferState::Rejected
                | MediaTransferState::Cancelled
                | MediaTransferState::Corrupt
        ) {
            object.chunk_addresses.fill(None);
            object.verified_bitmap.fill(0);
            object.verified_bytes = 0;
        }
        self.persist_object(&object, rng)?;
        if matches!(
            state,
            MediaTransferState::Rejected
                | MediaTransferState::Cancelled
                | MediaTransferState::Corrupt
        ) {
            self.garbage_collect_media_files(false)?;
        }
        Ok(())
    }

    /// Commit one already end-to-end-encrypted chunk as a locally sealed file.
    ///
    /// The temp file is fsynced, atomically renamed, and only then is the
    /// sealed address map and progress bit committed in SQLite.
    pub fn commit_media_chunk(
        &mut self,
        local_id: &[u8; 16],
        index: u32,
        sealed_chunk: &[u8],
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 32]> {
        if sealed_chunk.len() != ATTACHMENT_SEALED_CHUNK_LEN {
            return Err(StoreError::MediaState);
        }
        let mut object = self.require_object(local_id)?;
        let slot = usize::try_from(index).map_err(|_| StoreError::MediaState)?;
        if slot >= object.chunk_addresses.len() {
            return Err(StoreError::MediaState);
        }
        let address = bulk_hash(sealed_chunk);
        if let Some(existing) = object.chunk_addresses[slot] {
            if existing == address && self.chunk_path(&address).is_file() {
                return Ok(address);
            }
            return Err(StoreError::MediaState);
        }

        let final_path = self.chunk_path(&address);
        let existing_valid = if final_path.exists() {
            fs::read(&final_path)
                .ok()
                .and_then(|local| self.k_media.open(&media_chunk_ad(&address), &local).ok())
                .is_some_and(|stored| stored == sealed_chunk)
        } else {
            false
        };
        if !existing_valid {
            let projected = sealed_chunk.len() as u64 + LOCAL_SEAL_OVERHEAD;
            let usage = self.media_usage()?;
            if usage
                .sealed_file_bytes
                .checked_add(projected)
                .is_none_or(|bytes| bytes > self.media_limits.store_bytes)
                || usage
                    .incomplete_bytes
                    .checked_add(projected)
                    .is_none_or(|bytes| bytes > self.media_limits.incomplete_bytes)
            {
                return Err(StoreError::MediaQuota);
            }
            let available = fs2::available_space(&self.media_dir)?;
            if available
                .checked_sub(projected)
                .is_none_or(|remaining| remaining < self.media_limits.free_space_reserve)
            {
                return Err(StoreError::LowStorage);
            }

            let ad = media_chunk_ad(&address);
            let sealed_local = self.k_media.seal(&ad, sealed_chunk, rng);
            let temp_path = self.temp_chunk_path(rng);
            write_private_file(&temp_path, &sealed_local)?;
            if final_path.exists() {
                fs::remove_file(&final_path)?;
            }
            match fs::rename(&temp_path, &final_path) {
                Ok(()) => sync_media_directory(&self.media_dir)?,
                Err(error) if final_path.exists() => {
                    fs::remove_file(&temp_path)?;
                    let _ = error;
                }
                Err(error) => return Err(error.into()),
            }
        }

        object.chunk_addresses[slot] = Some(address);
        set_bit(&mut object.verified_bitmap, slot);
        object.verified_bytes = verified_bytes(&object)?;
        if !matches!(object.state, MediaTransferState::Complete) {
            object.state = MediaTransferState::Transferring;
        }
        let sealed = seal_record(&self.k_media, MEDIA_OBJECT_AD, &object, rng)?;
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE media_objects SET blob = ?2 WHERE id = ?1",
            params![object.local_id.as_slice(), sealed],
        )?;
        tx.commit()?;
        Ok(address)
    }

    /// Read and locally unseal one end-to-end encrypted chunk record.
    pub fn read_media_chunk(&self, local_id: &[u8; 16], index: u32) -> Result<Vec<u8>> {
        let object = self.require_object(local_id)?;
        let address = object
            .chunk_addresses
            .get(index as usize)
            .and_then(|address| *address)
            .ok_or(StoreError::MediaState)?;
        let locally_sealed = fs::read(self.chunk_path(&address))?;
        let chunk = self
            .k_media
            .open(&media_chunk_ad(&address), &locally_sealed)?;
        if chunk.len() != ATTACHMENT_SEALED_CHUNK_LEN || bulk_hash(&chunk) != address {
            return Err(StoreError::MediaState);
        }
        Ok(chunk)
    }

    /// Mark an object complete only after every durable chunk and the final
    /// streamed object hash have been verified by the caller.
    pub fn mark_media_complete(
        &self,
        local_id: &[u8; 16],
        verified_hash: &[u8; 32],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let mut object = self.require_object(local_id)?;
        if &object.content_hash != verified_hash
            || object.chunk_addresses.iter().any(Option::is_none)
            || object.verified_bytes != object.total_len
            || object
                .chunk_addresses
                .iter()
                .flatten()
                .any(|address| !self.chunk_path(address).is_file())
        {
            object.state = MediaTransferState::Corrupt;
            object.chunk_addresses.fill(None);
            object.verified_bitmap.fill(0);
            object.verified_bytes = 0;
            self.persist_object(&object, rng)?;
            self.garbage_collect_media_files(false)?;
            return Err(StoreError::MediaState);
        }
        object.state = MediaTransferState::Complete;
        self.persist_object(&object, rng)
    }

    /// Delete one object row and garbage-collect chunk files no longer referenced.
    pub fn delete_media_object(&mut self, local_id: &[u8; 16]) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM media_objects WHERE id = ?1",
            params![local_id.as_slice()],
        )?;
        tx.commit()?;
        self.garbage_collect_media_files(false).map(|_| ())
    }

    /// Aggregate current media usage without exposing paths or addresses.
    pub fn media_usage(&self) -> Result<MediaUsage> {
        let mut usage = MediaUsage::default();
        for entry in fs::read_dir(&self.media_dir)? {
            let entry = entry?;
            if is_chunk_filename(&entry.file_name()) {
                usage.sealed_file_bytes = usage
                    .sealed_file_bytes
                    .checked_add(entry.metadata()?.len())
                    .ok_or(StoreError::MediaQuota)?;
            }
        }
        let mut incomplete = HashSet::new();
        for record in self.media_objects()? {
            if let MediaRecord::Available(object) = record {
                if object.state.active() {
                    usage.active_objects += 1;
                }
                if object.state.incomplete() {
                    incomplete.extend(object.chunk_addresses.into_iter().flatten());
                }
            }
        }
        for address in incomplete {
            if let Ok(metadata) = fs::metadata(self.chunk_path(&address)) {
                usage.incomplete_bytes = usage
                    .incomplete_bytes
                    .checked_add(metadata.len())
                    .ok_or(StoreError::MediaQuota)?;
            }
        }
        Ok(usage)
    }

    /// Reconcile temp files, missing references, and unreferenced final files.
    ///
    /// Call this once after `Store::open`, when the node has supplied an RNG.
    pub fn reconcile_media(&mut self, rng: &mut impl CryptoRngCore) -> Result<MediaReconciliation> {
        let mut report = MediaReconciliation {
            stale_temps_removed: remove_stale_temps(&self.media_dir)?,
            ..MediaReconciliation::default()
        };
        let records = self.media_objects()?;
        for record in records {
            match record {
                MediaRecord::Unavailable { .. } => report.unknown_records += 1,
                MediaRecord::Available(mut object) => {
                    let missing = object
                        .chunk_addresses
                        .iter()
                        .flatten()
                        .any(|address| !self.chunk_path(address).is_file());
                    if missing && object.state != MediaTransferState::Unavailable {
                        object.state = MediaTransferState::Unavailable;
                        self.persist_object(&object, rng)?;
                        report.missing_objects += 1;
                    }
                }
            }
        }
        report.orphan_files_removed =
            self.garbage_collect_media_files(report.unknown_records > 0)?;
        Ok(report)
    }

    fn get_media_record<T: DeserializeOwned>(
        &self,
        table: &str,
        ad: &[u8],
        local_id: &[u8; 16],
    ) -> Result<Option<MediaRecord<T>>> {
        let sql = format!("SELECT blob FROM {table} WHERE id = ?1");
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row(&sql, params![local_id.as_slice()], |row| row.get(0))
            .optional()?;
        sealed
            .map(|sealed| self.decode_media_record(ad, *local_id, &sealed))
            .transpose()
    }

    fn media_records<T: DeserializeOwned>(
        &self,
        table: &str,
        ad: &[u8],
    ) -> Result<Vec<MediaRecord<T>>> {
        let sql = format!("SELECT id, blob FROM {table} ORDER BY rowid");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut records = Vec::new();
        for row in rows {
            let (local_id, sealed) = row?;
            let local_id: [u8; 16] = local_id.try_into().map_err(|_| StoreError::Serialization)?;
            records.push(self.decode_media_record(ad, local_id, &sealed)?);
        }
        Ok(records)
    }

    fn decode_media_record<T: DeserializeOwned>(
        &self,
        ad: &[u8],
        local_id: [u8; 16],
        sealed: &[u8],
    ) -> Result<MediaRecord<T>> {
        let plain = self.k_media.open(ad, sealed)?;
        let Some((&version, encoded)) = plain.split_first() else {
            return Err(StoreError::Serialization);
        };
        if version != MEDIA_RECORD_VERSION {
            return Ok(MediaRecord::Unavailable { local_id, version });
        }
        let (record, remainder) =
            postcard::take_from_bytes(encoded).map_err(|_| StoreError::Serialization)?;
        if !remainder.is_empty() {
            return Err(StoreError::Serialization);
        }
        Ok(MediaRecord::Available(record))
    }

    fn require_transfer(&self, local_id: &[u8; 16]) -> Result<MediaTransferRecord> {
        match self.get_media_transfer(local_id)? {
            Some(MediaRecord::Available(record)) => Ok(record),
            _ => Err(StoreError::MediaState),
        }
    }

    fn require_object(&self, local_id: &[u8; 16]) -> Result<MediaObjectRecord> {
        match self.get_media_object(local_id)? {
            Some(MediaRecord::Available(record)) => Ok(record),
            _ => Err(StoreError::MediaState),
        }
    }

    fn persist_object(
        &self,
        object: &MediaObjectRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        validate_object(object)?;
        let sealed = seal_record(&self.k_media, MEDIA_OBJECT_AD, object, rng)?;
        self.conn.execute(
            "UPDATE media_objects SET blob = ?2 WHERE id = ?1",
            params![object.local_id.as_slice(), sealed],
        )?;
        Ok(())
    }

    fn enforce_active_limits(
        &self,
        transfer: &MediaTransferRecord,
        replacing: Option<[u8; 16]>,
    ) -> Result<()> {
        let mut global = 0usize;
        let mut per_peer = 0usize;
        for record in self.media_objects()? {
            let MediaRecord::Available(object) = record else {
                continue;
            };
            if replacing == Some(object.local_id) || !object.state.active() {
                continue;
            }
            global += 1;
            let owner = self.require_transfer(&object.transfer_id)?;
            if owner.peer == transfer.peer && owner.direction == transfer.direction {
                per_peer += 1;
            }
        }
        let peer_limit = match transfer.direction {
            MediaDirection::Inbound => self.media_limits.active_inbound_per_peer,
            MediaDirection::Outbound => self.media_limits.active_outbound_per_peer,
        };
        if global >= self.media_limits.active_global || per_peer >= peer_limit {
            return Err(StoreError::MediaQuota);
        }
        Ok(())
    }

    fn chunk_path(&self, address: &[u8; 32]) -> PathBuf {
        self.media_dir.join(hex_address(address))
    }

    fn temp_chunk_path(&self, rng: &mut impl CryptoRngCore) -> PathBuf {
        let mut suffix = [0u8; 8];
        rng.fill_bytes(&mut suffix);
        self.media_dir.join(format!(".tmp-{}", hex_bytes(&suffix)))
    }

    fn garbage_collect_media_files(&self, preserve_unknown: bool) -> Result<usize> {
        if preserve_unknown {
            return Ok(0);
        }
        let mut referenced = HashSet::new();
        for record in self.media_objects()? {
            if let MediaRecord::Available(object) = record {
                referenced.extend(object.chunk_addresses.into_iter().flatten());
            }
        }
        let referenced: HashSet<String> = referenced.iter().map(hex_address).collect();
        let mut removed = 0;
        for entry in fs::read_dir(&self.media_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            if is_chunk_filename(&name) && !referenced.contains(name.to_string_lossy().as_ref()) {
                fs::remove_file(entry.path())?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

fn seal_record<T: Serialize>(
    key: &kult_crypto::StorageKey,
    ad: &[u8],
    record: &T,
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<u8>> {
    let encoded = postcard::to_allocvec(record).map_err(|_| StoreError::Serialization)?;
    let mut versioned = Vec::with_capacity(1 + encoded.len());
    versioned.push(MEDIA_RECORD_VERSION);
    versioned.extend_from_slice(&encoded);
    Ok(key.seal(ad, &versioned, rng))
}

fn validate_transfer(record: &MediaTransferRecord) -> Result<()> {
    if record.entitled_peers.len() > MAX_ENTITLEMENTS {
        return Err(StoreError::MediaQuota);
    }
    let mut peers = record.entitled_peers.clone();
    peers.sort_unstable();
    peers.dedup();
    if peers.len() != record.entitled_peers.len() {
        return Err(StoreError::MediaState);
    }
    Ok(())
}

fn validate_object(record: &MediaObjectRecord) -> Result<()> {
    let max_len = match record.role {
        0 => MAX_PRIMARY_OBJECT_LEN,
        1 => MAX_PREVIEW_OBJECT_LEN,
        _ => return Err(StoreError::MediaState),
    };
    let max_chunks = if record.role == 0 {
        MAX_PRIMARY_CHUNKS
    } else {
        MAX_PREVIEW_CHUNKS
    };
    if record.total_len > max_len
        || record.chunk_count != attachment_chunk_count(record.total_len)
        || record.chunk_count > max_chunks
        || record.verified_bitmap.len() != bitmap_len(record.chunk_count)
        || record.chunk_addresses.len() != record.chunk_count as usize
        || record.media_type.is_empty()
        || record.media_type.len() > MAX_ATTACHMENT_MEDIA_TYPE_LEN
        || record
            .filename
            .as_ref()
            .is_some_and(|name| name.len() > MAX_ATTACHMENT_FILENAME_LEN)
        || record.verified_bytes > record.total_len
        || !valid_media_type(&record.media_type)
        || !valid_filename(record.filename.as_deref())
        || (record.role == 1
            && (!matches!(record.media_type.as_str(), "image/jpeg" | "image/png")
                || record.filename.is_some()))
    {
        return Err(StoreError::MediaState);
    }
    for (index, address) in record.chunk_addresses.iter().enumerate() {
        if address.is_some() != bit_is_set(&record.verified_bitmap, index) {
            return Err(StoreError::MediaState);
        }
    }
    if verified_bytes(record)? != record.verified_bytes {
        return Err(StoreError::MediaState);
    }
    Ok(())
}

fn valid_media_type(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_ATTACHMENT_MEDIA_TYPE_LEN || !bytes.is_ascii() {
        return false;
    }
    let mut slash = None;
    for (index, &byte) in bytes.iter().enumerate() {
        if byte == b'/' {
            if slash.replace(index).is_some() {
                return false;
            }
        } else if !matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-')
        {
            return false;
        }
    }
    matches!(slash, Some(index) if index > 0 && index + 1 < bytes.len())
}

fn valid_filename(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return true;
    };
    !value.is_empty()
        && value.len() <= MAX_ATTACHMENT_FILENAME_LEN
        && !matches!(value, "." | "..")
        && !value.contains(['/', '\\'])
        && !value
            .chars()
            .any(|c| matches!(c as u32, 0x00..=0x1f | 0x7f..=0x9f))
}

fn bitmap_len(chunk_count: u32) -> usize {
    (chunk_count as usize).div_ceil(8)
}

fn set_bit(bitmap: &mut [u8], index: usize) {
    bitmap[index / 8] |= 1 << (index % 8);
}

fn bit_is_set(bitmap: &[u8], index: usize) -> bool {
    bitmap[index / 8] & (1 << (index % 8)) != 0
}

fn verified_bytes(record: &MediaObjectRecord) -> Result<u64> {
    let mut total = 0u64;
    for (index, address) in record.chunk_addresses.iter().enumerate() {
        if address.is_some() {
            let start = (index as u64)
                .checked_mul(49_152)
                .ok_or(StoreError::MediaState)?;
            let len = core::cmp::min(record.total_len - start, 49_152);
            total = total.checked_add(len).ok_or(StoreError::MediaState)?;
        }
    }
    Ok(total)
}

fn media_chunk_ad(address: &[u8; 32]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(32 + MEDIA_CHUNK_AD.len());
    ad.extend_from_slice(address);
    ad.extend_from_slice(MEDIA_CHUNK_AD);
    ad
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    set_private_file_permissions(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn remove_stale_temps(directory: &Path) -> Result<usize> {
    let mut removed = 0;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(".tmp-") {
            fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    Ok(removed)
}

fn is_chunk_filename(name: &OsString) -> bool {
    let name = name.to_string_lossy();
    name.len() == 64 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn hex_address(address: &[u8; 32]) -> String {
    hex_bytes(address)
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_media_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_media_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kult_crypto::KdfProfile;
    use rand::{rngs::StdRng, SeedableRng};

    const TEST_KDF: KdfProfile = KdfProfile {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };

    #[test]
    fn unknown_record_versions_are_quarantined_without_partial_decode() {
        let mut rng = StdRng::seed_from_u64(0x1500);
        let dir = tempfile::tempdir().unwrap();
        let store =
            Store::create(&dir.path().join("versions.db"), b"pass", TEST_KDF, &mut rng).unwrap();
        let local_id = [9u8; 16];
        let sealed = store
            .k_media
            .seal(MEDIA_OBJECT_AD, &[2, 0xff, 0xff], &mut rng);
        store
            .conn
            .execute(
                "INSERT INTO media_objects (id, blob) VALUES (?1, ?2)",
                params![local_id.as_slice(), sealed],
            )
            .unwrap();
        assert_eq!(
            store.get_media_object(&local_id).unwrap(),
            Some(MediaRecord::Unavailable {
                local_id,
                version: 2
            })
        );
    }
}
