//! Core ADR-0015 attachment transfer engine.

use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom, Write};

use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::api::{
    AttachmentConversation, AttachmentDirection, AttachmentInfo, AttachmentMetadata,
    AttachmentObjectInfo,
};
use crate::{Event, Node, NodeError, Result};
use kult_crypto::{
    attachment_pairwise_scope_id, open_attachment_chunk, seal_attachment_chunk,
    AttachmentChunkContext, AttachmentChunkScope,
};
use kult_protocol::{
    decode_attachment_bulk_record, decode_content, delivery_token, encode_attachment,
    encode_attachment_bulk_record, epoch_day, pad, pad_to_minimum, validate_missing_ranges,
    AttachmentBulkOperation, AttachmentBulkRecord, AttachmentManifest, AttachmentObject,
    AttachmentReason, AttachmentRole, AttachmentScope, DecodedAttachmentBulkRecord, DecodedContent,
    Envelope, EnvelopeKind, MailboxKey, MissingRange, CONTENT_FORMAT_V1, CONTENT_KIND_ATTACHMENT,
    MAX_PREVIEW_OBJECT_LEN, MAX_PRIMARY_OBJECT_LEN,
};
use kult_store::{
    DeliveryState, Direction, GroupDelivery, GroupMessageRecord, MediaDirection, MediaObjectRecord,
    MediaRecord, MediaScope, MediaTransferRecord, MediaTransferState, MessageRecord, QueueClass,
    QueueItem, Store, StoreError,
};

const BULK_CONTROL_PADDING_FLOOR: usize = 4096;
const MISSING_RETRY_SECS: u64 = 30;
const MAX_AUTOMATIC_IDLE_SECS: u64 = 30 * 86_400;
const MAX_CHUNKS_PER_REQUEST: usize = 8;

#[derive(Clone)]
struct ManifestObject {
    object_id: [u8; 16],
    role: AttachmentRole,
    total_len: u64,
    chunk_count: u32,
    content_hash: [u8; 32],
}

struct ManifestData {
    attachment_key: [u8; 32],
    objects: Vec<ManifestObject>,
}

pub(crate) struct GroupAttachmentOffer {
    pub(crate) group: [u8; 32],
    pub(crate) author: [u8; 32],
    pub(crate) entitled_peers: Vec<[u8; 32]>,
}

struct AttachmentSourceDetails {
    total_len: u64,
    content_hash: [u8; 32],
}

fn attachment_source_details<R: Read + Seek>(
    source: &mut R,
    max_len: u64,
) -> Result<AttachmentSourceDetails> {
    let total_len = source.seek(SeekFrom::End(0))?;
    if total_len > max_len {
        return Err(NodeError::InvalidAttachment);
    }
    source.seek(SeekFrom::Start(0))?;
    let mut hasher = blake3::Hasher::new();
    let mut remaining = total_len;
    let mut buffer = Zeroizing::new(vec![0u8; kult_crypto::ATTACHMENT_CHUNK_DATA_LEN]);
    while remaining != 0 {
        let take = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| NodeError::InvalidAttachment)?;
        source.read_exact(&mut buffer[..take])?;
        hasher.update(&buffer[..take]);
        remaining -= take as u64;
    }
    source.seek(SeekFrom::Start(0))?;
    Ok(AttachmentSourceDetails {
        total_len,
        content_hash: *hasher.finalize().as_bytes(),
    })
}

fn validate_preview_metadata(metadata: &AttachmentMetadata) -> Result<()> {
    if metadata.filename.is_some()
        || !matches!(metadata.media_type.as_str(), "image/jpeg" | "image/png")
    {
        return Err(NodeError::InvalidAttachment);
    }
    Ok(())
}

fn media_object_record(
    local_id: [u8; 16],
    transfer_id: [u8; 16],
    object_id: [u8; 16],
    role: AttachmentRole,
    details: &AttachmentSourceDetails,
    metadata: &AttachmentMetadata,
) -> MediaObjectRecord {
    let chunk_count = kult_protocol::attachment_chunk_count(details.total_len);
    MediaObjectRecord {
        local_id,
        transfer_id,
        object_id,
        role: role as u8,
        total_len: details.total_len,
        chunk_count,
        content_hash: details.content_hash,
        media_type: metadata.media_type.clone(),
        filename: if role == AttachmentRole::Primary {
            metadata.filename.clone()
        } else {
            None
        },
        state: MediaTransferState::Queued,
        verified_bitmap: vec![0; (chunk_count as usize).div_ceil(8)],
        chunk_addresses: vec![None; chunk_count as usize],
        verified_bytes: 0,
    }
}

fn import_object<R: Read + Seek>(
    store: &mut Store,
    source: &mut R,
    attachment_key: &[u8; 32],
    context: AttachmentChunkContext,
    local_object_id: &[u8; 16],
    rng: &mut impl CryptoRngCore,
) -> Result<()> {
    let mut buffer = Zeroizing::new(vec![0u8; kult_crypto::ATTACHMENT_CHUNK_DATA_LEN]);
    for index in 0..context.chunk_count {
        let consumed = u64::from(index) * kult_crypto::ATTACHMENT_CHUNK_DATA_LEN as u64;
        let actual_len = usize::try_from(
            (context.total_len - consumed).min(kult_crypto::ATTACHMENT_CHUNK_DATA_LEN as u64),
        )
        .map_err(|_| NodeError::InvalidAttachment)?;
        source.read_exact(&mut buffer[..actual_len])?;
        let sealed = seal_attachment_chunk(attachment_key, &context, index, &buffer[..actual_len])?;
        store.commit_media_chunk(local_object_id, index, &sealed, rng)?;
    }
    store.mark_media_complete(local_object_id, &context.content_hash, rng)?;
    Ok(())
}

fn import_group_object<R: Read + Seek>(
    store: &mut Store,
    source: &mut R,
    attachment_key: &[u8; 32],
    context: AttachmentChunkContext,
    local_object_ids: &[[u8; 16]],
    rng: &mut impl CryptoRngCore,
) -> Result<()> {
    let mut buffer = Zeroizing::new(vec![0u8; kult_crypto::ATTACHMENT_CHUNK_DATA_LEN]);
    for index in 0..context.chunk_count {
        let consumed = u64::from(index) * kult_crypto::ATTACHMENT_CHUNK_DATA_LEN as u64;
        let actual_len = usize::try_from(
            (context.total_len - consumed).min(kult_crypto::ATTACHMENT_CHUNK_DATA_LEN as u64),
        )
        .map_err(|_| NodeError::InvalidAttachment)?;
        source.read_exact(&mut buffer[..actual_len])?;
        let sealed = seal_attachment_chunk(attachment_key, &context, index, &buffer[..actual_len])?;
        for local_object_id in local_object_ids {
            store.commit_media_chunk(local_object_id, index, &sealed, rng)?;
        }
    }
    for local_object_id in local_object_ids {
        store.mark_media_complete(local_object_id, &context.content_hash, rng)?;
    }
    Ok(())
}

impl Node {
    /// Import one pairwise attachment from a bounded seekable stream.
    ///
    /// The stream is read twice: once to hash exact bytes for the manifest,
    /// then again in 49,152-byte chunks for encryption. No plaintext media is
    /// written by the node. The offer remains local and queued until a tick
    /// observes both authenticated Attachment support and a fresh non-airtime
    /// route for the peer.
    pub fn send_attachment<R: Read + Seek>(
        &mut self,
        peer: &[u8; 32],
        metadata: &AttachmentMetadata,
        source: &mut R,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        self.send_attachment_with_preview::<R, R>(peer, metadata, source, None, now, rng)
    }

    /// Import one pairwise attachment with an optional locally generated
    /// JPEG/PNG preview. Both streams are sealed directly into the media
    /// store and the preview is subject to the protocol's 256 KiB ceiling.
    pub fn send_attachment_with_preview<R: Read + Seek, P: Read + Seek>(
        &mut self,
        peer: &[u8; 32],
        metadata: &AttachmentMetadata,
        source: &mut R,
        mut preview: Option<(&AttachmentMetadata, &mut P)>,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        self.store
            .get_contact(peer)?
            .ok_or(NodeError::UnknownPeer)?;
        if !self.peer_supports_attachment(peer)? {
            return Err(NodeError::AttachmentUnsupported);
        }

        let primary = attachment_source_details(source, MAX_PRIMARY_OBJECT_LEN)?;
        let preview_details = match preview.as_mut() {
            Some((preview_metadata, preview_source)) => {
                validate_preview_metadata(preview_metadata)?;
                Some(attachment_source_details(
                    *preview_source,
                    MAX_PREVIEW_OBJECT_LEN,
                )?)
            }
            None => None,
        };

        let mut content_id = [0u8; 16];
        let mut transfer_id = [0u8; 16];
        let mut local_object_id = [0u8; 16];
        let mut object_id = [0u8; 16];
        let mut preview_local_object_id = [0u8; 16];
        let mut preview_object_id = [0u8; 16];
        let mut attachment_key = [0u8; 32];
        for value in [
            &mut content_id[..],
            &mut transfer_id[..],
            &mut local_object_id[..],
            &mut object_id[..],
            &mut preview_local_object_id[..],
            &mut preview_object_id[..],
            &mut attachment_key[..],
        ] {
            rng.fill_bytes(value);
        }

        let chunk_count = kult_protocol::attachment_chunk_count(primary.total_len);
        let preview_manifest = preview.as_ref().zip(preview_details.as_ref()).map(
            |((preview_metadata, _), details)| AttachmentObject {
                role: AttachmentRole::Preview,
                object_id: preview_object_id,
                total_len: details.total_len,
                chunk_data_len: kult_protocol::ATTACHMENT_CHUNK_DATA_LEN,
                chunk_count: kult_protocol::attachment_chunk_count(details.total_len),
                content_hash: details.content_hash,
                media_type: &preview_metadata.media_type,
                filename: None,
            },
        );
        let manifest = AttachmentManifest {
            attachment_key,
            primary: AttachmentObject {
                role: AttachmentRole::Primary,
                object_id,
                total_len: primary.total_len,
                chunk_data_len: kult_protocol::ATTACHMENT_CHUNK_DATA_LEN,
                chunk_count,
                content_hash: primary.content_hash,
                media_type: &metadata.media_type,
                filename: metadata.filename.as_deref(),
            },
            preview: preview_manifest,
        };
        let frame =
            encode_attachment(content_id, &manifest).map_err(|_| NodeError::InvalidAttachment)?;
        let me = self.identity.public().ed;
        let scope_id = attachment_pairwise_scope_id(&me, peer);
        let transfer = MediaTransferRecord {
            local_id: transfer_id,
            peer: *peer,
            direction: MediaDirection::Outbound,
            scope: MediaScope::Pairwise,
            scope_id,
            manifest_author: me,
            manifest_content_id: content_id,
            entitled_peers: vec![*peer],
            state: MediaTransferState::Queued,
            updated_at: now,
        };
        let object = media_object_record(
            local_object_id,
            transfer_id,
            object_id,
            AttachmentRole::Primary,
            &primary,
            metadata,
        );

        self.store.put_message(
            &MessageRecord {
                id: content_id,
                peer: *peer,
                direction: Direction::Outbound,
                state: DeliveryState::Queued,
                timestamp: now,
                body: frame,
                wire_id: None,
            },
            rng,
        )?;
        self.store.put_media_transfer(&transfer, rng)?;
        self.store.put_media_object(&object, rng)?;
        if let (Some((preview_metadata, _)), Some(details)) =
            (preview.as_ref(), preview_details.as_ref())
        {
            self.store.put_media_object(
                &media_object_record(
                    preview_local_object_id,
                    transfer_id,
                    preview_object_id,
                    AttachmentRole::Preview,
                    details,
                    preview_metadata,
                ),
                rng,
            )?;
        }

        import_object(
            &mut self.store,
            source,
            &attachment_key,
            AttachmentChunkContext {
                scope: AttachmentChunkScope::Pairwise,
                scope_id,
                manifest_author: me,
                manifest_content_id: content_id,
                object_id,
                role: AttachmentRole::Primary as u8,
                total_len: primary.total_len,
                chunk_count,
                content_hash: primary.content_hash,
            },
            &local_object_id,
            rng,
        )?;
        if let (Some((_, preview_source)), Some(details)) = (preview.as_mut(), preview_details) {
            import_object(
                &mut self.store,
                *preview_source,
                &attachment_key,
                AttachmentChunkContext {
                    scope: AttachmentChunkScope::Pairwise,
                    scope_id,
                    manifest_author: me,
                    manifest_content_id: content_id,
                    object_id: preview_object_id,
                    role: AttachmentRole::Preview as u8,
                    total_len: details.total_len,
                    chunk_count: kult_protocol::attachment_chunk_count(details.total_len),
                    content_hash: details.content_hash,
                },
                &preview_local_object_id,
                rng,
            )?;
        }
        self.emit_attachment_update(&transfer_id)?;
        Ok(content_id)
    }

    /// Import one sender-key group attachment while retaining a single
    /// manifest and a single deterministic sealed-chunk set for every
    /// entitled member. Network fan-out remains held until all current
    /// co-members have authenticated support and fresh non-airtime routes.
    pub fn send_group_attachment<R: Read + Seek>(
        &mut self,
        group: &[u8; 32],
        metadata: &AttachmentMetadata,
        source: &mut R,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        self.send_group_attachment_with_preview::<R, R>(group, metadata, source, None, now, rng)
    }

    /// Import one sender-key group attachment with an optional locally
    /// generated JPEG/PNG preview. Each object is encrypted once and the
    /// deterministic sealed chunks are retained for every entitled member.
    pub fn send_group_attachment_with_preview<R: Read + Seek, P: Read + Seek>(
        &mut self,
        group: &[u8; 32],
        metadata: &AttachmentMetadata,
        source: &mut R,
        mut preview: Option<(&AttachmentMetadata, &mut P)>,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let group_record = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        let me = self.identity.public().ed;
        let peers: Vec<[u8; 32]> = group_record
            .members
            .iter()
            .filter(|member| member.peer != me)
            .map(|member| member.peer)
            .collect();
        if peers.is_empty() {
            return Err(NodeError::InvalidAttachment);
        }
        for peer in &peers {
            if !self.peer_supports_attachment(peer)? {
                return Err(NodeError::AttachmentUnsupported);
            }
        }

        let primary = attachment_source_details(source, MAX_PRIMARY_OBJECT_LEN)?;
        let preview_details = match preview.as_mut() {
            Some((preview_metadata, preview_source)) => {
                validate_preview_metadata(preview_metadata)?;
                Some(attachment_source_details(
                    *preview_source,
                    MAX_PREVIEW_OBJECT_LEN,
                )?)
            }
            None => None,
        };

        let mut content_id = [0u8; 16];
        let mut object_id = [0u8; 16];
        let mut preview_object_id = [0u8; 16];
        let mut attachment_key = [0u8; 32];
        rng.fill_bytes(&mut content_id);
        rng.fill_bytes(&mut object_id);
        rng.fill_bytes(&mut preview_object_id);
        rng.fill_bytes(&mut attachment_key);
        let chunk_count = kult_protocol::attachment_chunk_count(primary.total_len);
        let preview_manifest = preview.as_ref().zip(preview_details.as_ref()).map(
            |((preview_metadata, _), details)| AttachmentObject {
                role: AttachmentRole::Preview,
                object_id: preview_object_id,
                total_len: details.total_len,
                chunk_data_len: kult_protocol::ATTACHMENT_CHUNK_DATA_LEN,
                chunk_count: kult_protocol::attachment_chunk_count(details.total_len),
                content_hash: details.content_hash,
                media_type: &preview_metadata.media_type,
                filename: None,
            },
        );
        let manifest = AttachmentManifest {
            attachment_key,
            primary: AttachmentObject {
                role: AttachmentRole::Primary,
                object_id,
                total_len: primary.total_len,
                chunk_data_len: kult_protocol::ATTACHMENT_CHUNK_DATA_LEN,
                chunk_count,
                content_hash: primary.content_hash,
                media_type: &metadata.media_type,
                filename: metadata.filename.as_deref(),
            },
            preview: preview_manifest,
        };
        let frame =
            encode_attachment(content_id, &manifest).map_err(|_| NodeError::InvalidAttachment)?;
        self.store.put_group_message(
            &GroupMessageRecord {
                id: content_id,
                group: *group,
                sender: me,
                direction: Direction::Outbound,
                timestamp: now,
                body: frame,
                deliveries: peers
                    .iter()
                    .map(|peer| GroupDelivery {
                        peer: *peer,
                        wire_id: None,
                        state: DeliveryState::Queued,
                    })
                    .collect(),
                wire_body: None,
            },
            rng,
        )?;

        let primary_context = AttachmentChunkContext {
            scope: AttachmentChunkScope::Group,
            scope_id: *group,
            manifest_author: me,
            manifest_content_id: content_id,
            object_id,
            role: AttachmentRole::Primary as u8,
            total_len: primary.total_len,
            chunk_count,
            content_hash: primary.content_hash,
        };
        let mut rows = Vec::new();
        for peer in &peers {
            let mut transfer_id = [0u8; 16];
            let mut local_object_id = [0u8; 16];
            let mut preview_local_object_id = [0u8; 16];
            rng.fill_bytes(&mut transfer_id);
            rng.fill_bytes(&mut local_object_id);
            rng.fill_bytes(&mut preview_local_object_id);
            let transfer = MediaTransferRecord {
                local_id: transfer_id,
                peer: *peer,
                direction: MediaDirection::Outbound,
                scope: MediaScope::Group,
                scope_id: *group,
                manifest_author: me,
                manifest_content_id: content_id,
                entitled_peers: peers.clone(),
                state: MediaTransferState::Queued,
                updated_at: now,
            };
            let object = media_object_record(
                local_object_id,
                transfer_id,
                object_id,
                AttachmentRole::Primary,
                &primary,
                metadata,
            );
            let preview_object = preview.as_ref().zip(preview_details.as_ref()).map(
                |((preview_metadata, _), details)| {
                    media_object_record(
                        preview_local_object_id,
                        transfer_id,
                        preview_object_id,
                        AttachmentRole::Preview,
                        details,
                        preview_metadata,
                    )
                },
            );
            self.store.put_media_transfer(&transfer, rng)?;
            self.store.put_media_object(&object, rng)?;
            if let Some(preview_object) = &preview_object {
                self.store.put_media_object(preview_object, rng)?;
            }
            rows.push((transfer, object, preview_object));
        }

        let primary_ids = rows
            .iter()
            .map(|(_, object, _)| object.local_id)
            .collect::<Vec<_>>();
        import_group_object(
            &mut self.store,
            source,
            &attachment_key,
            primary_context,
            &primary_ids,
            rng,
        )?;
        if let (Some((_, preview_source)), Some(details)) = (preview.as_mut(), preview_details) {
            let preview_ids = rows
                .iter()
                .filter_map(|(_, _, object)| object.as_ref().map(|object| object.local_id))
                .collect::<Vec<_>>();
            import_group_object(
                &mut self.store,
                *preview_source,
                &attachment_key,
                AttachmentChunkContext {
                    scope: AttachmentChunkScope::Group,
                    scope_id: *group,
                    manifest_author: me,
                    manifest_content_id: content_id,
                    object_id: preview_object_id,
                    role: AttachmentRole::Preview as u8,
                    total_len: details.total_len,
                    chunk_count: kult_protocol::attachment_chunk_count(details.total_len),
                    content_hash: details.content_hash,
                },
                &preview_ids,
                rng,
            )?;
        }
        for (transfer, _, _) in &rows {
            self.emit_attachment_update(&transfer.local_id)?;
        }
        Ok(content_id)
    }

    /// Return every supported attachment transfer as render-safe state.
    pub fn attachments(&self) -> Result<Vec<AttachmentInfo>> {
        self.store
            .media_transfers()?
            .into_iter()
            .filter_map(|record| match record {
                MediaRecord::Available(transfer) => Some(self.attachment_info(&transfer)),
                MediaRecord::Unavailable { .. } => None,
            })
            .collect()
    }

    /// Stream the completed primary object to an application-provided
    /// protected handle. The node never chooses a path or creates a plaintext
    /// temporary file; export is an explicit local user action.
    pub fn export_attachment<W: Write>(
        &self,
        transfer_id: &[u8; 16],
        destination: &mut W,
    ) -> Result<()> {
        self.export_attachment_object(transfer_id, false, destination)
    }

    /// Stream a completed primary or preview object to an
    /// application-provided protected handle. Preview export is intended for
    /// transient local rendering and never selects a filesystem path itself.
    pub fn export_attachment_object<W: Write>(
        &self,
        transfer_id: &[u8; 16],
        preview: bool,
        destination: &mut W,
    ) -> Result<()> {
        let transfer = self.require_attachment(transfer_id)?;
        let object = self
            .store
            .media_objects_for_transfer(transfer_id)?
            .into_iter()
            .find(|object| {
                object.role
                    == if preview {
                        AttachmentRole::Preview as u8
                    } else {
                        AttachmentRole::Primary as u8
                    }
            })
            .ok_or(NodeError::UnknownAttachment)?;
        if object.state != MediaTransferState::Complete {
            return Err(NodeError::InvalidAttachment);
        }
        let manifest = self.load_manifest(&transfer)?;
        let manifest_object = manifest
            .objects
            .iter()
            .find(|candidate| candidate.object_id == object.object_id)
            .ok_or(NodeError::InvalidAttachment)?;
        let context = self.chunk_context(&transfer, manifest_object);
        let mut hasher = blake3::Hasher::new();
        for index in 0..object.chunk_count {
            let sealed = self.store.read_media_chunk(&object.local_id, index)?;
            let plain = Zeroizing::new(open_attachment_chunk(
                &manifest.attachment_key,
                &context,
                index,
                &sealed,
            )?);
            hasher.update(&plain);
            destination.write_all(&plain)?;
        }
        if hasher.finalize().as_bytes() != &object.content_hash {
            return Err(NodeError::InvalidAttachment);
        }
        destination.flush()?;
        Ok(())
    }

    /// Accept an inbound offer. The next eligible tick requests all missing
    /// chunks; no network record is created while only airtime links exist.
    pub fn accept_attachment(
        &mut self,
        transfer_id: &[u8; 16],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let transfer = self.require_attachment(transfer_id)?;
        if transfer.direction != MediaDirection::Inbound
            || !matches!(
                transfer.state,
                MediaTransferState::Offered
                    | MediaTransferState::AwaitingConsent
                    | MediaTransferState::Rejected
                    | MediaTransferState::Cancelled
            )
        {
            return Err(NodeError::InvalidAttachment);
        }
        let mut all_empty = true;
        for object in self.store.media_objects_for_transfer(transfer_id)? {
            if object.chunk_count == 0 {
                self.store
                    .mark_media_complete(&object.local_id, &object.content_hash, rng)?;
            } else {
                all_empty = false;
                self.store.set_media_object_state(
                    &object.local_id,
                    MediaTransferState::Queued,
                    rng,
                )?;
            }
        }
        self.store.set_media_transfer_state(
            transfer_id,
            if all_empty {
                MediaTransferState::Complete
            } else {
                MediaTransferState::Queued
            },
            now,
            rng,
        )?;
        self.emit_attachment_update(transfer_id)
    }

    /// Durably reject an inbound offer and release partial data.
    pub fn reject_attachment(
        &mut self,
        transfer_id: &[u8; 16],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let transfer = self.require_attachment(transfer_id)?;
        if transfer.direction != MediaDirection::Inbound {
            return Err(NodeError::InvalidAttachment);
        }
        self.finish_attachment_locally(&transfer, MediaTransferState::Rejected, now, true, rng)
    }

    /// Cancel transfer activity in either direction and release unreferenced
    /// partial data. A later explicit inbound accept may restart the offer.
    pub fn cancel_attachment(
        &mut self,
        transfer_id: &[u8; 16],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let transfer = self.require_attachment(transfer_id)?;
        self.finish_attachment_locally(&transfer, MediaTransferState::Cancelled, now, true, rng)
    }

    /// Pause an active transfer while retaining every verified chunk.
    pub fn pause_attachment(
        &mut self,
        transfer_id: &[u8; 16],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let transfer = self.require_attachment(transfer_id)?;
        if !matches!(
            transfer.state,
            MediaTransferState::Queued | MediaTransferState::Transferring
        ) {
            return Err(NodeError::InvalidAttachment);
        }
        if transfer.direction == MediaDirection::Inbound {
            for object in self.store.media_objects_for_transfer(transfer_id)? {
                if object.state != MediaTransferState::Complete {
                    self.store.set_media_object_state(
                        &object.local_id,
                        MediaTransferState::Paused,
                        rng,
                    )?;
                }
            }
        }
        self.store
            .set_media_transfer_state(transfer_id, MediaTransferState::Paused, now, rng)?;
        self.attachment_request_at.remove(transfer_id);
        self.emit_attachment_update(transfer_id)
    }

    /// Resume a paused transfer and reset its explicit retry window.
    pub fn resume_attachment(
        &mut self,
        transfer_id: &[u8; 16],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let transfer = self.require_attachment(transfer_id)?;
        if transfer.state != MediaTransferState::Paused {
            return Err(NodeError::InvalidAttachment);
        }
        if transfer.direction == MediaDirection::Inbound {
            for object in self.store.media_objects_for_transfer(transfer_id)? {
                if object.state != MediaTransferState::Complete {
                    self.store.set_media_object_state(
                        &object.local_id,
                        MediaTransferState::Queued,
                        rng,
                    )?;
                }
            }
        }
        let state = if transfer.direction == MediaDirection::Outbound
            && self.attachment_manifest_was_queued(&transfer)?
        {
            MediaTransferState::Transferring
        } else {
            MediaTransferState::Queued
        };
        self.store
            .set_media_transfer_state(transfer_id, state, now, rng)?;
        self.attachment_request_at.remove(transfer_id);
        self.emit_attachment_update(transfer_id)
    }

    pub(crate) fn record_pairwise_attachment_offer(
        &mut self,
        peer: [u8; 32],
        content_id: [u8; 16],
        manifest: &AttachmentManifest<'_>,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let mut transfer_id = [0u8; 16];
        rng.fill_bytes(&mut transfer_id);
        let me = self.identity.public().ed;
        let transfer = MediaTransferRecord {
            local_id: transfer_id,
            peer,
            direction: MediaDirection::Inbound,
            scope: MediaScope::Pairwise,
            scope_id: attachment_pairwise_scope_id(&me, &peer),
            manifest_author: peer,
            manifest_content_id: content_id,
            entitled_peers: vec![me],
            state: MediaTransferState::AwaitingConsent,
            updated_at: now,
        };
        self.store.put_media_transfer(&transfer, rng)?;
        for descriptor in core::iter::once(&manifest.primary).chain(manifest.preview.as_ref()) {
            let mut local_id = [0u8; 16];
            rng.fill_bytes(&mut local_id);
            self.store.put_media_object(
                &MediaObjectRecord {
                    local_id,
                    transfer_id,
                    object_id: descriptor.object_id,
                    role: descriptor.role as u8,
                    total_len: descriptor.total_len,
                    chunk_count: descriptor.chunk_count,
                    content_hash: descriptor.content_hash,
                    media_type: descriptor.media_type.to_owned(),
                    filename: descriptor.filename.map(str::to_owned),
                    state: MediaTransferState::AwaitingConsent,
                    verified_bitmap: vec![0; (descriptor.chunk_count as usize).div_ceil(8)],
                    chunk_addresses: vec![None; descriptor.chunk_count as usize],
                    verified_bytes: 0,
                },
                rng,
            )?;
        }
        self.emit_attachment_update(&transfer_id)?;
        Ok(transfer_id)
    }

    pub(crate) fn record_group_attachment_offer(
        &mut self,
        offer: GroupAttachmentOffer,
        content_id: [u8; 16],
        manifest: &AttachmentManifest<'_>,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let mut transfer_id = [0u8; 16];
        rng.fill_bytes(&mut transfer_id);
        let transfer = MediaTransferRecord {
            local_id: transfer_id,
            peer: offer.author,
            direction: MediaDirection::Inbound,
            scope: MediaScope::Group,
            scope_id: offer.group,
            manifest_author: offer.author,
            manifest_content_id: content_id,
            entitled_peers: offer.entitled_peers,
            state: MediaTransferState::AwaitingConsent,
            updated_at: now,
        };
        self.store.put_media_transfer(&transfer, rng)?;
        for descriptor in core::iter::once(&manifest.primary).chain(manifest.preview.as_ref()) {
            let mut local_id = [0u8; 16];
            rng.fill_bytes(&mut local_id);
            self.store.put_media_object(
                &MediaObjectRecord {
                    local_id,
                    transfer_id,
                    object_id: descriptor.object_id,
                    role: descriptor.role as u8,
                    total_len: descriptor.total_len,
                    chunk_count: descriptor.chunk_count,
                    content_hash: descriptor.content_hash,
                    media_type: descriptor.media_type.to_owned(),
                    filename: descriptor.filename.map(str::to_owned),
                    state: MediaTransferState::AwaitingConsent,
                    verified_bitmap: vec![0; (descriptor.chunk_count as usize).div_ceil(8)],
                    chunk_addresses: vec![None; descriptor.chunk_count as usize],
                    verified_bytes: 0,
                },
                rng,
            )?;
        }
        self.emit_attachment_update(&transfer_id)?;
        Ok(transfer_id)
    }

    pub(crate) async fn activate_attachment_transfers(
        &mut self,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let transfers: Vec<_> = self
            .store
            .media_transfers()?
            .into_iter()
            .filter_map(|record| match record {
                MediaRecord::Available(transfer) => Some(transfer),
                MediaRecord::Unavailable { .. } => None,
            })
            .collect();
        for transfer in &transfers {
            if transfer.direction == MediaDirection::Inbound
                && transfer.state == MediaTransferState::Transferring
                && now.saturating_sub(transfer.updated_at) > MAX_AUTOMATIC_IDLE_SECS
            {
                self.pause_attachment(&transfer.local_id, now, rng)?;
                continue;
            }
            if !self.peer_supports_attachment(&transfer.peer)?
                || !self.carrier_allows_bulk(&transfer.peer, now)?
            {
                continue;
            }
            match transfer.direction {
                MediaDirection::Outbound
                    if transfer.scope == MediaScope::Pairwise
                        && transfer.state == MediaTransferState::Queued =>
                {
                    if self.queue_pairwise_attachment_manifest(transfer, now, rng)? {
                        self.store.set_media_transfer_state(
                            &transfer.local_id,
                            MediaTransferState::Transferring,
                            now,
                            rng,
                        )?;
                        self.emit_attachment_update(&transfer.local_id)?;
                    }
                }
                MediaDirection::Inbound
                    if transfer.state == MediaTransferState::Queued
                        || (transfer.state == MediaTransferState::Transferring
                            && self
                                .attachment_request_at
                                .get(&transfer.local_id)
                                .is_none_or(|last| {
                                    now.saturating_sub(*last) >= MISSING_RETRY_SECS
                                })) =>
                {
                    let mut queued = false;
                    for object in self.store.media_objects_for_transfer(&transfer.local_id)? {
                        if object.state == MediaTransferState::Complete {
                            let role = role_from_u8(object.role)?;
                            let complete = self.bulk_record(
                                transfer,
                                object.object_id,
                                AttachmentBulkOperation::Complete {
                                    role,
                                    content_hash: object.content_hash,
                                },
                            )?;
                            self.queue_attachment_bulk(&transfer.peer, &complete, now, rng)?;
                            queued = true;
                            continue;
                        }
                        let ranges = missing_ranges(&object);
                        if ranges.is_empty() {
                            continue;
                        }
                        let role = role_from_u8(object.role)?;
                        let record = self.bulk_record(
                            transfer,
                            object.object_id,
                            AttachmentBulkOperation::RequestMissing { role, ranges },
                        )?;
                        self.queue_attachment_bulk(&transfer.peer, &record, now, rng)?;
                        queued = true;
                    }
                    if queued {
                        self.store.set_media_transfer_state(
                            &transfer.local_id,
                            if self
                                .store
                                .media_objects_for_transfer(&transfer.local_id)?
                                .iter()
                                .all(|object| object.state == MediaTransferState::Complete)
                            {
                                MediaTransferState::Complete
                            } else {
                                MediaTransferState::Transferring
                            },
                            transfer.updated_at,
                            rng,
                        )?;
                        self.attachment_request_at.insert(transfer.local_id, now);
                        self.emit_attachment_update(&transfer.local_id)?;
                    }
                }
                _ => {}
            }
            if transfer.updated_at != 0
                && matches!(
                    transfer.state,
                    MediaTransferState::Rejected | MediaTransferState::Cancelled
                )
            {
                let Some(object) = self
                    .store
                    .media_objects_for_transfer(&transfer.local_id)?
                    .into_iter()
                    .next()
                else {
                    continue;
                };
                let operation = match transfer.state {
                    MediaTransferState::Rejected => {
                        AttachmentBulkOperation::Reject(AttachmentReason::User)
                    }
                    MediaTransferState::Cancelled => {
                        AttachmentBulkOperation::Cancel(AttachmentReason::User)
                    }
                    _ => unreachable!("terminal state checked above"),
                };
                let terminal = self.bulk_record(transfer, object.object_id, operation)?;
                self.queue_attachment_bulk(&transfer.peer, &terminal, now, rng)?;
                self.store
                    .set_media_transfer_state(&transfer.local_id, transfer.state, 0, rng)?;
            }
        }

        let group_manifests: BTreeSet<([u8; 32], [u8; 16])> = transfers
            .iter()
            .filter(|transfer| {
                transfer.scope == MediaScope::Group
                    && transfer.direction == MediaDirection::Outbound
                    && transfer.state == MediaTransferState::Queued
            })
            .map(|transfer| (transfer.scope_id, transfer.manifest_content_id))
            .collect();
        for (group, content_id) in group_manifests {
            let copies: Vec<_> = transfers
                .iter()
                .filter(|transfer| {
                    transfer.scope == MediaScope::Group
                        && transfer.direction == MediaDirection::Outbound
                        && transfer.scope_id == group
                        && transfer.manifest_content_id == content_id
                })
                .collect();
            let mut eligible = !copies.is_empty();
            for transfer in &copies {
                if transfer.state != MediaTransferState::Queued
                    || !self.peer_supports_attachment(&transfer.peer)?
                    || !self.carrier_allows_bulk(&transfer.peer, now)?
                {
                    eligible = false;
                    break;
                }
            }
            if eligible && self.queue_group_attachment_manifest(&group, &content_id, now, rng)? {
                for transfer in copies {
                    self.store.set_media_transfer_state(
                        &transfer.local_id,
                        MediaTransferState::Transferring,
                        now,
                        rng,
                    )?;
                    self.emit_attachment_update(&transfer.local_id)?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn apply_attachment_bulk(
        &mut self,
        peer: [u8; 32],
        body: &[u8],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let DecodedAttachmentBulkRecord::Record(record) = decode_attachment_bulk_record(body)
        else {
            return Ok(());
        };
        match record.operation {
            AttachmentBulkOperation::RequestMissing { role, ref ranges } => {
                let Some(transfer) = ignore_unknown(self.resolve_bulk_transfer(
                    &record,
                    &peer,
                    MediaDirection::Outbound,
                ))?
                else {
                    return Ok(());
                };
                if transfer.state == MediaTransferState::Paused {
                    return Ok(());
                }
                let Some(object) =
                    ignore_unknown(self.resolve_bulk_object(&transfer, record.object_id, role))?
                else {
                    return Ok(());
                };
                if validate_missing_ranges(ranges, object.chunk_count).is_err() {
                    return Ok(());
                }
                let mut served = 0usize;
                'ranges: for range in ranges {
                    for index in range.start..range.start + range.count {
                        if served == MAX_CHUNKS_PER_REQUEST {
                            break 'ranges;
                        }
                        let sealed = self.store.read_media_chunk(&object.local_id, index)?;
                        let chunk = self.bulk_record(
                            &transfer,
                            object.object_id,
                            AttachmentBulkOperation::Chunk {
                                role,
                                index,
                                sealed_chunk: &sealed,
                            },
                        )?;
                        self.queue_attachment_bulk(&peer, &chunk, now, rng)?;
                        served += 1;
                    }
                }
                self.store.set_media_transfer_state(
                    &transfer.local_id,
                    MediaTransferState::Transferring,
                    now,
                    rng,
                )?;
            }
            AttachmentBulkOperation::Chunk {
                role,
                index,
                sealed_chunk,
            } => {
                let Some(transfer) = ignore_unknown(self.resolve_bulk_transfer(
                    &record,
                    &peer,
                    MediaDirection::Inbound,
                ))?
                else {
                    return Ok(());
                };
                let Some(object) =
                    ignore_unknown(self.resolve_bulk_object(&transfer, record.object_id, role))?
                else {
                    return Ok(());
                };
                if index >= object.chunk_count {
                    return Ok(());
                }
                let manifest = self.load_manifest(&transfer)?;
                let Some(manifest_object) = manifest.objects.iter().find(|candidate| {
                    candidate.object_id == object.object_id && candidate.role == role
                }) else {
                    return Ok(());
                };
                let context = self.chunk_context(&transfer, manifest_object);
                if open_attachment_chunk(&manifest.attachment_key, &context, index, sealed_chunk)
                    .is_err()
                {
                    let corrupt = self.bulk_record(
                        &transfer,
                        object.object_id,
                        AttachmentBulkOperation::Cancel(AttachmentReason::Corrupt),
                    )?;
                    self.finish_attachment_locally(
                        &transfer,
                        MediaTransferState::Corrupt,
                        now,
                        false,
                        rng,
                    )?;
                    self.queue_attachment_bulk(&peer, &corrupt, now, rng)?;
                    return Ok(());
                }
                match self
                    .store
                    .commit_media_chunk(&object.local_id, index, sealed_chunk, rng)
                {
                    Ok(_) => {}
                    Err(StoreError::MediaQuota) => {
                        let reject = self.bulk_record(
                            &transfer,
                            object.object_id,
                            AttachmentBulkOperation::Reject(AttachmentReason::Quota),
                        )?;
                        self.finish_attachment_locally(
                            &transfer,
                            MediaTransferState::Rejected,
                            now,
                            false,
                            rng,
                        )?;
                        self.queue_attachment_bulk(&peer, &reject, now, rng)?;
                        return Ok(());
                    }
                    Err(StoreError::LowStorage) => {
                        let reject = self.bulk_record(
                            &transfer,
                            object.object_id,
                            AttachmentBulkOperation::Reject(AttachmentReason::LowStorage),
                        )?;
                        self.finish_attachment_locally(
                            &transfer,
                            MediaTransferState::Rejected,
                            now,
                            false,
                            rng,
                        )?;
                        self.queue_attachment_bulk(&peer, &reject, now, rng)?;
                        return Ok(());
                    }
                    Err(StoreError::MediaState) => {
                        let corrupt = self.bulk_record(
                            &transfer,
                            object.object_id,
                            AttachmentBulkOperation::Cancel(AttachmentReason::Corrupt),
                        )?;
                        self.finish_attachment_locally(
                            &transfer,
                            MediaTransferState::Corrupt,
                            now,
                            false,
                            rng,
                        )?;
                        self.queue_attachment_bulk(&peer, &corrupt, now, rng)?;
                        return Ok(());
                    }
                    Err(error) => return Err(error.into()),
                }
                self.store.set_media_transfer_state(
                    &transfer.local_id,
                    MediaTransferState::Transferring,
                    now,
                    rng,
                )?;
                let stored = match self.store.get_media_object(&object.local_id)? {
                    Some(MediaRecord::Available(stored)) => stored,
                    _ => return Err(NodeError::UnknownAttachment),
                };
                if stored.chunk_addresses.iter().all(Option::is_some) {
                    let mut hasher = blake3::Hasher::new();
                    for chunk_index in 0..stored.chunk_count {
                        let sealed = self.store.read_media_chunk(&stored.local_id, chunk_index)?;
                        let plain = Zeroizing::new(open_attachment_chunk(
                            &manifest.attachment_key,
                            &context,
                            chunk_index,
                            &sealed,
                        )?);
                        hasher.update(&plain);
                    }
                    let verified_hash = *hasher.finalize().as_bytes();
                    if verified_hash != stored.content_hash {
                        let corrupt = self.bulk_record(
                            &transfer,
                            stored.object_id,
                            AttachmentBulkOperation::Cancel(AttachmentReason::Corrupt),
                        )?;
                        self.finish_attachment_locally(
                            &transfer,
                            MediaTransferState::Corrupt,
                            now,
                            false,
                            rng,
                        )?;
                        self.queue_attachment_bulk(&peer, &corrupt, now, rng)?;
                        return Ok(());
                    }
                    self.store
                        .mark_media_complete(&stored.local_id, &verified_hash, rng)?;
                    let complete = self.bulk_record(
                        &transfer,
                        stored.object_id,
                        AttachmentBulkOperation::Complete {
                            role,
                            content_hash: verified_hash,
                        },
                    )?;
                    self.queue_attachment_bulk(&peer, &complete, now, rng)?;
                    let all_complete = self
                        .store
                        .media_objects_for_transfer(&transfer.local_id)?
                        .iter()
                        .all(|candidate| candidate.state == MediaTransferState::Complete);
                    if all_complete {
                        self.store.set_media_transfer_state(
                            &transfer.local_id,
                            MediaTransferState::Complete,
                            now,
                            rng,
                        )?;
                    }
                }
                self.emit_attachment_update(&transfer.local_id)?;
            }
            AttachmentBulkOperation::Complete { role, content_hash } => {
                let Some(transfer) = ignore_unknown(self.resolve_bulk_transfer(
                    &record,
                    &peer,
                    MediaDirection::Outbound,
                ))?
                else {
                    return Ok(());
                };
                let Some(object) =
                    ignore_unknown(self.resolve_bulk_object(&transfer, record.object_id, role))?
                else {
                    return Ok(());
                };
                if object.content_hash != content_hash {
                    return Ok(());
                }
                // Completion acknowledgements can cross an explicit local
                // terminal decision in flight. A delayed acknowledgement
                // confirms remote receipt, but must not resurrect work the
                // user cancelled/rejected or that failed integrity locally.
                if matches!(
                    transfer.state,
                    MediaTransferState::Rejected
                        | MediaTransferState::Cancelled
                        | MediaTransferState::Corrupt
                ) {
                    return Ok(());
                }
                self.store.set_media_transfer_state(
                    &transfer.local_id,
                    MediaTransferState::Complete,
                    now,
                    rng,
                )?;
                self.emit_attachment_update(&transfer.local_id)?;
            }
            AttachmentBulkOperation::Cancel(_) => {
                let Some(transfer) =
                    ignore_unknown(self.resolve_bulk_transfer_any_direction(&record, &peer))?
                else {
                    return Ok(());
                };
                if !self
                    .store
                    .media_objects_for_transfer(&transfer.local_id)?
                    .iter()
                    .any(|object| object.object_id == record.object_id)
                {
                    return Ok(());
                }
                self.finish_attachment_locally(
                    &transfer,
                    MediaTransferState::Cancelled,
                    now,
                    false,
                    rng,
                )?;
            }
            AttachmentBulkOperation::Reject(_) => {
                let Some(transfer) = ignore_unknown(self.resolve_bulk_transfer(
                    &record,
                    &peer,
                    MediaDirection::Outbound,
                ))?
                else {
                    return Ok(());
                };
                if !self
                    .store
                    .media_objects_for_transfer(&transfer.local_id)?
                    .iter()
                    .any(|object| object.object_id == record.object_id)
                {
                    return Ok(());
                }
                self.finish_attachment_locally(
                    &transfer,
                    MediaTransferState::Rejected,
                    now,
                    false,
                    rng,
                )?;
            }
        }
        Ok(())
    }

    pub(crate) fn peer_supports_attachment(&self, peer: &[u8; 32]) -> Result<bool> {
        Ok(self
            .store
            .get_capabilities(peer)?
            .is_some_and(|capabilities| {
                capabilities.supports(CONTENT_FORMAT_V1, CONTENT_KIND_ATTACHMENT)
            }))
    }

    fn queue_pairwise_attachment_manifest(
        &mut self,
        transfer: &MediaTransferRecord,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let Some(mut message) =
            self.store
                .messages_with(&transfer.peer)?
                .into_iter()
                .find(|message| {
                    message.direction == Direction::Outbound
                        && message.id == transfer.manifest_content_id
                })
        else {
            return Err(NodeError::UnknownAttachment);
        };
        if message.wire_id.is_some() {
            return Ok(false);
        }
        let Some(session) = self.sessions.get_mut(&transfer.peer) else {
            return Ok(false);
        };
        let ratchet = session.encrypt(rng, now, &pad(&message.body)?, &[]);
        let token = delivery_token(
            &MailboxKey::from_bytes(*session.mailbox_key()),
            epoch_day(now),
            &transfer.peer,
        );
        self.store.put_session(&transfer.peer, session, rng)?;
        let envelope = Envelope::new(EnvelopeKind::Message, token, ratchet.encode());
        message.wire_id = Some(envelope.content_id());
        self.store.update_message(&message, rng)?;
        self.store.queue_push(
            &QueueItem {
                peer: transfer.peer,
                msg_id: Some(message.id),
                group_msg_id: None,
                class: QueueClass::Bulk,
                envelope,
            },
            rng,
        )?;
        Ok(true)
    }

    fn queue_attachment_bulk(
        &mut self,
        peer: &[u8; 32],
        record: &AttachmentBulkRecord<'_>,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let Some(session) = self.sessions.get_mut(peer) else {
            return Err(NodeError::NoSession);
        };
        let payload = encode_attachment_bulk_record(record)?;
        let padded = pad_to_minimum(&payload, BULK_CONTROL_PADDING_FLOOR)?;
        let ratchet = session.encrypt(rng, now, &padded, &[]);
        let token = delivery_token(
            &MailboxKey::from_bytes(*session.mailbox_key()),
            epoch_day(now),
            peer,
        );
        self.store.put_session(peer, session, rng)?;
        self.store.queue_push(
            &QueueItem {
                peer: *peer,
                msg_id: None,
                group_msg_id: None,
                class: QueueClass::Bulk,
                envelope: Envelope::new(EnvelopeKind::Receipt, token, ratchet.encode()),
            },
            rng,
        )?;
        Ok(())
    }

    fn bulk_record<'a>(
        &self,
        transfer: &MediaTransferRecord,
        object_id: [u8; 16],
        operation: AttachmentBulkOperation<'a>,
    ) -> Result<AttachmentBulkRecord<'a>> {
        Ok(AttachmentBulkRecord {
            scope: match transfer.scope {
                MediaScope::Pairwise => AttachmentScope::Pairwise,
                MediaScope::Group => AttachmentScope::Group,
            },
            scope_id: transfer.scope_id,
            manifest_author: transfer.manifest_author,
            manifest_content_id: transfer.manifest_content_id,
            object_id,
            operation,
        })
    }

    fn resolve_bulk_transfer(
        &self,
        record: &AttachmentBulkRecord<'_>,
        peer: &[u8; 32],
        direction: MediaDirection,
    ) -> Result<MediaTransferRecord> {
        self.store
            .media_transfers()?
            .into_iter()
            .find_map(|stored| match stored {
                MediaRecord::Available(transfer)
                    if transfer.direction == direction
                        && transfer.peer == *peer
                        && transfer.scope_id == record.scope_id
                        && transfer.manifest_author == record.manifest_author
                        && transfer.manifest_content_id == record.manifest_content_id
                        && matches!(
                            (transfer.scope, record.scope),
                            (MediaScope::Pairwise, AttachmentScope::Pairwise)
                                | (MediaScope::Group, AttachmentScope::Group)
                        )
                        && (direction == MediaDirection::Inbound
                            || transfer.entitled_peers.contains(peer)) =>
                {
                    Some(transfer)
                }
                _ => None,
            })
            .ok_or(NodeError::UnknownAttachment)
    }

    fn resolve_bulk_transfer_any_direction(
        &self,
        record: &AttachmentBulkRecord<'_>,
        peer: &[u8; 32],
    ) -> Result<MediaTransferRecord> {
        match self.resolve_bulk_transfer(record, peer, MediaDirection::Inbound) {
            Ok(transfer) => Ok(transfer),
            Err(NodeError::UnknownAttachment) => {
                self.resolve_bulk_transfer(record, peer, MediaDirection::Outbound)
            }
            Err(error) => Err(error),
        }
    }

    fn resolve_bulk_object(
        &self,
        transfer: &MediaTransferRecord,
        object_id: [u8; 16],
        role: AttachmentRole,
    ) -> Result<MediaObjectRecord> {
        self.store
            .media_objects_for_transfer(&transfer.local_id)?
            .into_iter()
            .find(|object| object.object_id == object_id && object.role == role as u8)
            .ok_or(NodeError::UnknownAttachment)
    }

    fn require_attachment(&self, transfer_id: &[u8; 16]) -> Result<MediaTransferRecord> {
        match self.store.get_media_transfer(transfer_id)? {
            Some(MediaRecord::Available(transfer)) => Ok(transfer),
            _ => Err(NodeError::UnknownAttachment),
        }
    }

    fn attachment_info(&self, transfer: &MediaTransferRecord) -> Result<AttachmentInfo> {
        let objects = self
            .store
            .media_objects_for_transfer(&transfer.local_id)?
            .into_iter()
            .map(|object| AttachmentObjectInfo {
                preview: object.role == AttachmentRole::Preview as u8,
                total_bytes: object.total_len,
                verified_bytes: object.verified_bytes,
                presentation: crate::classify_attachment_file(
                    &object.media_type,
                    object.filename.as_deref(),
                ),
                media_type: object.media_type,
                filename: object.filename,
                state: object.state,
            })
            .collect();
        Ok(AttachmentInfo {
            transfer_id: transfer.local_id,
            peer: transfer.peer,
            conversation: match transfer.scope {
                MediaScope::Pairwise => AttachmentConversation::Pairwise,
                MediaScope::Group => AttachmentConversation::Group,
            },
            group: (transfer.scope == MediaScope::Group).then_some(transfer.scope_id),
            direction: match transfer.direction {
                MediaDirection::Inbound => AttachmentDirection::Inbound,
                MediaDirection::Outbound => AttachmentDirection::Outbound,
            },
            author: transfer.manifest_author,
            content_id: transfer.manifest_content_id,
            state: transfer.state,
            objects,
        })
    }

    pub(crate) fn emit_attachment_update(&mut self, transfer_id: &[u8; 16]) -> Result<()> {
        let transfer = self.require_attachment(transfer_id)?;
        let attachment = self.attachment_info(&transfer)?;
        self.events
            .push_back(Event::AttachmentUpdated { attachment });
        Ok(())
    }

    fn finish_attachment_locally(
        &mut self,
        transfer: &MediaTransferRecord,
        state: MediaTransferState,
        now: u64,
        notify_remote: bool,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        if transfer.direction == MediaDirection::Inbound || state == MediaTransferState::Corrupt {
            for object in self.store.media_objects_for_transfer(&transfer.local_id)? {
                self.store
                    .set_media_object_state(&object.local_id, state, rng)?;
            }
        }
        self.store.set_media_transfer_state(
            &transfer.local_id,
            state,
            if notify_remote { now } else { 0 },
            rng,
        )?;
        self.attachment_request_at.remove(&transfer.local_id);
        self.emit_attachment_update(&transfer.local_id)
    }

    fn attachment_manifest_was_queued(&self, transfer: &MediaTransferRecord) -> Result<bool> {
        Ok(match transfer.scope {
            MediaScope::Pairwise => {
                self.store
                    .messages_with(&transfer.peer)?
                    .iter()
                    .any(|message| {
                        message.id == transfer.manifest_content_id && message.wire_id.is_some()
                    })
            }
            MediaScope::Group => self
                .store
                .group_messages(&transfer.scope_id)?
                .iter()
                .find(|message| message.id == transfer.manifest_content_id)
                .is_some_and(|message| {
                    message
                        .deliveries
                        .iter()
                        .any(|delivery| delivery.wire_id.is_some())
                }),
        })
    }

    fn load_manifest(&self, transfer: &MediaTransferRecord) -> Result<ManifestData> {
        let body = Zeroizing::new(
            match transfer.scope {
                MediaScope::Pairwise => self
                    .store
                    .messages_with(&transfer.peer)?
                    .into_iter()
                    .find(|message| message.id == transfer.manifest_content_id)
                    .map(|message| message.body),
                MediaScope::Group => self
                    .store
                    .group_messages(&transfer.scope_id)?
                    .into_iter()
                    .find(|message| {
                        message.id == transfer.manifest_content_id
                            && message.sender == transfer.manifest_author
                    })
                    .map(|message| message.body),
            }
            .ok_or(NodeError::UnknownAttachment)?,
        );
        let DecodedContent::Attachment { manifest, .. } = decode_content(&body) else {
            return Err(NodeError::InvalidAttachment);
        };
        Ok(ManifestData {
            attachment_key: manifest.attachment_key,
            objects: core::iter::once(manifest.primary)
                .chain(manifest.preview)
                .map(|object| ManifestObject {
                    object_id: object.object_id,
                    role: object.role,
                    total_len: object.total_len,
                    chunk_count: object.chunk_count,
                    content_hash: object.content_hash,
                })
                .collect(),
        })
    }

    fn chunk_context(
        &self,
        transfer: &MediaTransferRecord,
        object: &ManifestObject,
    ) -> AttachmentChunkContext {
        AttachmentChunkContext {
            scope: match transfer.scope {
                MediaScope::Pairwise => AttachmentChunkScope::Pairwise,
                MediaScope::Group => AttachmentChunkScope::Group,
            },
            scope_id: transfer.scope_id,
            manifest_author: transfer.manifest_author,
            manifest_content_id: transfer.manifest_content_id,
            object_id: object.object_id,
            role: object.role as u8,
            total_len: object.total_len,
            chunk_count: object.chunk_count,
            content_hash: object.content_hash,
        }
    }
}

fn role_from_u8(role: u8) -> Result<AttachmentRole> {
    match role {
        0 => Ok(AttachmentRole::Primary),
        1 => Ok(AttachmentRole::Preview),
        _ => Err(NodeError::InvalidAttachment),
    }
}

fn ignore_unknown<T>(result: Result<T>) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(NodeError::UnknownAttachment) => Ok(None),
        Err(error) => Err(error),
    }
}

fn missing_ranges(object: &MediaObjectRecord) -> Vec<MissingRange> {
    let mut ranges = Vec::new();
    let mut index = 0usize;
    while index < object.chunk_addresses.len() && ranges.len() < 64 {
        if object.chunk_addresses[index].is_some() {
            index += 1;
            continue;
        }
        let start = index;
        while index < object.chunk_addresses.len() && object.chunk_addresses[index].is_none() {
            index += 1;
        }
        ranges.push(MissingRange {
            start: start as u32,
            count: (index - start) as u32,
        });
    }
    ranges
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn authenticated_foreign_bulk_reference_is_a_terminal_noop() {
        let mut rng = StdRng::seed_from_u64(0x15ff);
        let dir = tempfile::tempdir().unwrap();
        let mut node = Node::create(
            &dir.path().join("node.db"),
            b"pass",
            kult_crypto::KdfProfile {
                m_cost_kib: 8,
                t_cost: 1,
                p_cost: 1,
            },
            &mut rng,
        )
        .unwrap();
        let record = AttachmentBulkRecord {
            scope: AttachmentScope::Pairwise,
            scope_id: [1; 32],
            manifest_author: [2; 32],
            manifest_content_id: [3; 16],
            object_id: [4; 16],
            operation: AttachmentBulkOperation::Cancel(AttachmentReason::User),
        };
        let encoded = encode_attachment_bulk_record(&record).unwrap();
        node.apply_attachment_bulk([2; 32], &encoded, 1_800_000_000, &mut rng)
            .unwrap();
        assert!(node.attachments().unwrap().is_empty());
        assert!(node.drain_events().is_empty());
    }
}
