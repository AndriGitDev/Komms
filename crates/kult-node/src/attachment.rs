//! Core ADR-0015 attachment transfer engine.

use std::collections::BTreeSet;
use std::io::{Read, Seek, SeekFrom, Write};

use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use crate::api::{
    AttachmentConversation, AttachmentDirection, AttachmentInfo, AttachmentMetadata,
    AttachmentObjectInfo,
};
use crate::{CommitPlan, Event, Node, NodeError, Result};
use kult_crypto::{
    attachment_pairwise_scope_id, open_attachment_chunk, seal_attachment_chunk,
    AttachmentChunkContext, AttachmentChunkScope,
};
use kult_protocol::{
    decode_attachment_bulk_record, decode_content, delivery_token, encode_attachment,
    encode_attachment_bulk_record, encode_ephemeral, encode_view_once_attachment_payload,
    epoch_day, pad, pad_to_minimum, validate_missing_ranges, AttachmentBulkOperation,
    AttachmentBulkRecord, AttachmentManifest, AttachmentObject, AttachmentReason, AttachmentRole,
    AttachmentScope, DecodedAttachmentBulkRecord, DecodedContent, Envelope, EnvelopeKind,
    Ephemeral, MailboxKey, MissingRange, CONTENT_KIND_ATTACHMENT, CONTENT_KIND_EPHEMERAL,
    MAX_EPHEMERAL_LIFETIME_SECS, MAX_PREVIEW_OBJECT_LEN, MAX_PRIMARY_OBJECT_LEN,
    MIN_EPHEMERAL_LIFETIME_SECS,
};
use kult_store::{
    AttachmentStagePlan, AttachmentStatePlan, DeferredControlRecord, DeliveryState, Direction,
    EphemeralConversation, EphemeralMode, EphemeralRecord, EphemeralState, EphemeralTransition,
    GroupDelivery, GroupMessageDelete, GroupMessageRecord, MaintenancePlan, MediaDelete,
    MediaDirection, MediaObjectRecord, MediaObjectTransition, MediaRecord, MediaScope,
    MediaTransferRecord, MediaTransferState, MediaTransferTransition, MessageDelete,
    MessageDeviceDeliveryRecord, MessageRecord, MessageTransition, PairwiseSendPlan, QueueClass,
    QueueDelete, QueueItem, SessionTransition, Store, StoreError,
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

fn media_object_with_state(
    before: &MediaObjectRecord,
    state: MediaTransferState,
) -> MediaObjectRecord {
    let mut after = before.clone();
    after.state = state;
    if matches!(
        state,
        MediaTransferState::Rejected | MediaTransferState::Cancelled | MediaTransferState::Corrupt
    ) {
        after.chunk_addresses.fill(None);
        after.verified_bitmap.fill(0);
        after.verified_bytes = 0;
    }
    after
}

fn attachment_state_is_negative_terminal(state: MediaTransferState) -> bool {
    matches!(
        state,
        MediaTransferState::Rejected | MediaTransferState::Cancelled | MediaTransferState::Corrupt
    )
}

fn commit_media_object_pairs(
    store: &Store,
    pairs: &[(MediaObjectRecord, MediaObjectRecord)],
    rng: &mut impl CryptoRngCore,
) -> Result<()> {
    if pairs.is_empty() {
        return Ok(());
    }
    let objects = pairs
        .iter()
        .map(|(before, after)| MediaObjectTransition { before, after })
        .collect::<Vec<_>>();
    store.commit_plan(
        CommitPlan::AttachmentState(AttachmentStatePlan {
            media_transfers: &[],
            media_objects: &objects,
            delete_controls: &[],
            presentation_changed: false,
        }),
        rng,
    )?;
    Ok(())
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
        let staged = store.stage_media_chunk(local_object_id, index, &sealed, rng)?;
        if staged.before != staged.after {
            commit_media_object_pairs(store, &[(staged.before, staged.after)], rng)?;
        }
    }
    let complete = store.prepare_media_complete(local_object_id, &context.content_hash)?;
    commit_media_object_pairs(store, &[complete], rng)?;
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
        let mut pairs = Vec::new();
        for local_object_id in local_object_ids {
            let staged = store.stage_media_chunk(local_object_id, index, &sealed, rng)?;
            if staged.before != staged.after {
                pairs.push((staged.before, staged.after));
            }
        }
        commit_media_object_pairs(store, &pairs, rng)?;
    }
    let mut complete = Vec::new();
    for local_object_id in local_object_ids {
        complete.push(store.prepare_media_complete(local_object_id, &context.content_hash)?);
    }
    commit_media_object_pairs(store, &complete, rng)?;
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
        preview: Option<(&AttachmentMetadata, &mut P)>,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        self.send_pairwise_attachment_with_preview_mode(
            peer, metadata, source, preview, None, now, rng,
        )
    }

    /// Import a pairwise attachment whose decryptable local source is
    /// durably consumed by its first explicit open, with deadline fallback.
    pub fn send_view_once_attachment<R: Read + Seek>(
        &mut self,
        peer: &[u8; 32],
        metadata: &AttachmentMetadata,
        source: &mut R,
        lifetime_secs: u64,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        self.send_view_once_attachment_with_preview::<R, R>(
            peer,
            metadata,
            source,
            None,
            lifetime_secs,
            now,
            rng,
        )
    }

    /// View-once pairwise import with an optional bounded preview.
    #[allow(clippy::too_many_arguments)] // explicit streams, policy, time, and RNG boundaries
    pub fn send_view_once_attachment_with_preview<R: Read + Seek, P: Read + Seek>(
        &mut self,
        peer: &[u8; 32],
        metadata: &AttachmentMetadata,
        source: &mut R,
        preview: Option<(&AttachmentMetadata, &mut P)>,
        lifetime_secs: u64,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        if !(MIN_EPHEMERAL_LIFETIME_SECS..=MAX_EPHEMERAL_LIFETIME_SECS).contains(&lifetime_secs) {
            return Err(NodeError::InvalidEphemeral);
        }
        let expires_at = now
            .checked_add(lifetime_secs)
            .ok_or(NodeError::InvalidEphemeral)?;
        self.send_pairwise_attachment_with_preview_mode(
            peer,
            metadata,
            source,
            preview,
            Some(expires_at),
            now,
            rng,
        )
    }

    #[allow(clippy::too_many_arguments)] // shared ordinary/view-once import primitive
    fn send_pairwise_attachment_with_preview_mode<R: Read + Seek, P: Read + Seek>(
        &mut self,
        peer: &[u8; 32],
        metadata: &AttachmentMetadata,
        source: &mut R,
        mut preview: Option<(&AttachmentMetadata, &mut P)>,
        expires_at: Option<u64>,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        self.store
            .get_contact(peer)?
            .ok_or(NodeError::UnknownPeer)?;
        if !self.peer_supports_attachment(peer)? {
            return Err(NodeError::AttachmentUnsupported);
        }
        if expires_at.is_some()
            && (!self.peer_has_live_device_sessions(peer)?
                || !self.peer_supports_kind(peer, CONTENT_KIND_EPHEMERAL)?)
        {
            return Err(NodeError::EphemeralUnsupported);
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
        let frame = match expires_at {
            Some(deadline) => encode_ephemeral(
                content_id,
                &encode_view_once_attachment_payload(deadline, &manifest)?,
            )?,
            None => encode_attachment(content_id, &manifest)
                .map_err(|_| NodeError::InvalidAttachment)?,
        };
        let me = self.account.ed;
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

        let message = MessageRecord {
            id: content_id,
            peer: *peer,
            direction: Direction::Outbound,
            state: DeliveryState::Queued,
            timestamp: now,
            body: frame,
            wire_id: None,
        };
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
        let mut media_objects = vec![object.clone()];
        media_objects.extend(preview_object.iter().cloned());
        let ephemeral = expires_at.map(|expires_at| EphemeralRecord {
            conversation: EphemeralConversation::Pairwise(*peer),
            author: me,
            content_id,
            expires_at,
            mode: EphemeralMode::ViewOnceAttachment,
            state: EphemeralState::Active,
            transfer_ids: vec![transfer_id],
        });
        let receipt = self.store.commit_plan(
            CommitPlan::AttachmentStage(AttachmentStagePlan {
                message: Some(&message),
                group_message: None,
                media_transfers: core::slice::from_ref(&transfer),
                media_objects: &media_objects,
                ephemeral: ephemeral.as_ref(),
                presentation_changed: true,
            }),
            rng,
        )?;

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
        self.accept_commit_receipt(receipt, []);
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
        preview: Option<(&AttachmentMetadata, &mut P)>,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        self.send_group_attachment_with_preview_mode(
            group, metadata, source, preview, None, now, rng,
        )
    }

    /// Import one sender-key group view-once attachment with deadline fallback.
    pub fn send_group_view_once_attachment<R: Read + Seek>(
        &mut self,
        group: &[u8; 32],
        metadata: &AttachmentMetadata,
        source: &mut R,
        lifetime_secs: u64,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        self.send_group_view_once_attachment_with_preview::<R, R>(
            group,
            metadata,
            source,
            None,
            lifetime_secs,
            now,
            rng,
        )
    }

    /// Group view-once import with an optional bounded preview.
    #[allow(clippy::too_many_arguments)] // explicit streams, policy, time, and RNG boundaries
    pub fn send_group_view_once_attachment_with_preview<R: Read + Seek, P: Read + Seek>(
        &mut self,
        group: &[u8; 32],
        metadata: &AttachmentMetadata,
        source: &mut R,
        preview: Option<(&AttachmentMetadata, &mut P)>,
        lifetime_secs: u64,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        if !(MIN_EPHEMERAL_LIFETIME_SECS..=MAX_EPHEMERAL_LIFETIME_SECS).contains(&lifetime_secs) {
            return Err(NodeError::InvalidEphemeral);
        }
        let expires_at = now
            .checked_add(lifetime_secs)
            .ok_or(NodeError::InvalidEphemeral)?;
        self.send_group_attachment_with_preview_mode(
            group,
            metadata,
            source,
            preview,
            Some(expires_at),
            now,
            rng,
        )
    }

    #[allow(clippy::too_many_arguments)] // shared ordinary/view-once import primitive
    fn send_group_attachment_with_preview_mode<R: Read + Seek, P: Read + Seek>(
        &mut self,
        group: &[u8; 32],
        metadata: &AttachmentMetadata,
        source: &mut R,
        mut preview: Option<(&AttachmentMetadata, &mut P)>,
        expires_at: Option<u64>,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let group_record = self
            .store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        self.require_recipient_authenticated_group(group)?;
        let me = self.account.ed;
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
            if expires_at.is_some()
                && (!self.peer_has_live_device_sessions(peer)?
                    || !self.peer_supports_kind(peer, CONTENT_KIND_EPHEMERAL)?)
            {
                return Err(NodeError::EphemeralUnsupported);
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
        let frame = match expires_at {
            Some(deadline) => encode_ephemeral(
                content_id,
                &encode_view_once_attachment_payload(deadline, &manifest)?,
            )?,
            None => encode_attachment(content_id, &manifest)
                .map_err(|_| NodeError::InvalidAttachment)?,
        };
        let message = GroupMessageRecord {
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
            origin: kult_store::GroupOriginAuthentication::PendingOutboundV1 {
                sender_device: self.device_id(),
            },
        };

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
            rows.push((transfer, object, preview_object));
        }
        let transfers = rows
            .iter()
            .map(|(transfer, _, _)| transfer.clone())
            .collect::<Vec<_>>();
        let objects = rows
            .iter()
            .flat_map(|(_, object, preview)| {
                core::iter::once(object.clone()).chain(preview.iter().cloned())
            })
            .collect::<Vec<_>>();
        let ephemeral = expires_at.map(|expires_at| EphemeralRecord {
            conversation: EphemeralConversation::Group(*group),
            author: me,
            content_id,
            expires_at,
            mode: EphemeralMode::ViewOnceAttachment,
            state: EphemeralState::Active,
            transfer_ids: transfers.iter().map(|transfer| transfer.local_id).collect(),
        });
        let receipt = self.store.commit_plan(
            CommitPlan::AttachmentStage(AttachmentStagePlan {
                message: None,
                group_message: Some(&message),
                media_transfers: &transfers,
                media_objects: &objects,
                ephemeral: ephemeral.as_ref(),
                presentation_changed: true,
            }),
            rng,
        )?;

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
        self.accept_commit_receipt(receipt, []);
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
        if self.store.ephemeral_records()?.iter().any(|record| {
            record.mode == EphemeralMode::ViewOnceAttachment
                && record.transfer_ids.contains(transfer_id)
        }) {
            return Err(NodeError::ViewOnceExportForbidden);
        }
        self.export_attachment_object_inner(transfer_id, preview, destination)
    }

    fn export_attachment_object_inner<W: Write>(
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
        self.export_prepared_attachment(&transfer, &object, &manifest, destination)
    }

    fn export_prepared_attachment<W: Write>(
        &self,
        transfer: &MediaTransferRecord,
        object: &MediaObjectRecord,
        manifest: &ManifestData,
        destination: &mut W,
    ) -> Result<()> {
        let manifest_object = manifest
            .objects
            .iter()
            .find(|candidate| candidate.object_id == object.object_id)
            .ok_or(NodeError::InvalidAttachment)?;
        let context = self.chunk_context(transfer, manifest_object);
        let mut hasher = blake3::Hasher::new();
        for index in 0..object.chunk_count {
            let sealed = self.store.read_media_chunk_from_record(object, index)?;
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

    /// Consume a completed view-once primary into a protected application
    /// handle. The tombstone is durable before the first plaintext byte is
    /// emitted; success or I/O failure then removes every decryptable local
    /// source associated with the content id.
    pub fn consume_view_once_attachment<W: Write>(
        &mut self,
        transfer_id: &[u8; 16],
        destination: &mut W,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let mut record = self
            .store
            .ephemeral_records()?
            .into_iter()
            .find(|record| {
                record.mode == EphemeralMode::ViewOnceAttachment
                    && record.transfer_ids.contains(transfer_id)
            })
            .ok_or(NodeError::InvalidEphemeral)?;
        if record.state != EphemeralState::Active || now >= record.expires_at {
            return Err(NodeError::InvalidEphemeral);
        }
        let transfer = self.require_attachment(transfer_id)?;
        let object = self
            .store
            .media_objects_for_transfer(transfer_id)?
            .into_iter()
            .find(|object| object.role == AttachmentRole::Primary as u8)
            .ok_or(NodeError::UnknownAttachment)?;
        if object.state != MediaTransferState::Complete {
            return Err(NodeError::InvalidAttachment);
        }
        let manifest = self.load_manifest(&transfer)?;

        let before = record.clone();
        record.state = EphemeralState::Consumed;
        let me = self.account.ed;
        let mut pairwise_message = None;
        let mut group_message = None;
        match record.conversation {
            EphemeralConversation::Pairwise(peer) => {
                let direction = if record.author == me {
                    Direction::Outbound
                } else {
                    Direction::Inbound
                };
                pairwise_message = self
                    .store
                    .messages_with(&peer)?
                    .into_iter()
                    .find(|message| {
                        message.direction == direction && message.id == record.content_id
                    });
            }
            EphemeralConversation::Group(group) => {
                group_message = self
                    .store
                    .group_messages(&group)?
                    .into_iter()
                    .find(|message| {
                        message.sender == record.author && message.id == record.content_id
                    });
            }
        }
        let pairwise_delete = pairwise_message
            .as_ref()
            .map(|before| MessageDelete { before });
        let group_delete = group_message
            .as_ref()
            .map(|before| GroupMessageDelete { before });
        let delete_queue = self
            .store
            .queue_all()?
            .into_iter()
            .filter_map(|(sequence, item)| {
                let matches = match record.conversation {
                    EphemeralConversation::Pairwise(_) => item.msg_id == Some(record.content_id),
                    EphemeralConversation::Group(_) => item.group_msg_id == Some(record.content_id),
                };
                matches.then_some(QueueDelete {
                    sequence,
                    content_id: item.envelope.content_id(),
                })
            })
            .collect::<Vec<_>>();
        let mut media_rows = Vec::new();
        for transfer_id in &record.transfer_ids {
            if matches!(
                self.store.get_media_transfer(transfer_id)?,
                Some(MediaRecord::Available(_))
            ) {
                let object_ids = self
                    .store
                    .media_objects_for_transfer(transfer_id)?
                    .into_iter()
                    .map(|object| object.local_id)
                    .collect::<Vec<_>>();
                media_rows.push((*transfer_id, object_ids));
            }
        }
        let delete_media = media_rows
            .iter()
            .map(|(transfer_id, object_ids)| MediaDelete {
                transfer_id: *transfer_id,
                object_ids,
            })
            .collect::<Vec<_>>();
        let receipt = self.store.commit_plan(
            CommitPlan::Maintenance(MaintenancePlan {
                seen: &[],
                delete_pending: &[],
                delete_queue: &delete_queue,
                update_queue: &[],
                delete_replay: &[],
                messages: &[],
                deliveries: &[],
                group_messages: &[],
                groups: &[],
                ephemeral: &[EphemeralTransition {
                    before: Some(&before),
                    after: &record,
                }],
                delete_messages: pairwise_delete.as_slice(),
                delete_group_messages: group_delete.as_slice(),
                delete_media: &delete_media,
                delete_scheduled: &[],
                delete_sessions: &[],
                delete_capabilities: &[],
                clear_reset_markers: &[],
                delete_controls: &[],
                acknowledge_presentation: None,
                presentation_changed: true,
            }),
            rng,
        )?;
        for transfer_id in &record.transfer_ids {
            self.attachment_request_at.remove(transfer_id);
            self.attachment_request_target.remove(transfer_id);
        }
        let deleted = delete_queue
            .iter()
            .map(|delete| delete.sequence)
            .collect::<BTreeSet<_>>();
        self.held_notified
            .retain(|sequence| !deleted.contains(sequence));
        self.call_queue_deadlines
            .retain(|sequence, _| !deleted.contains(sequence));
        self.accept_commit_receipt(
            receipt,
            [Event::EphemeralRemoved {
                conversation: record.conversation,
                author: record.author,
                content_id: record.content_id,
                reason: EphemeralState::Consumed,
            }],
        );

        let export = self.export_prepared_attachment(&transfer, &object, &manifest, destination);
        let garbage = self.store.collect_media_garbage();
        export?;
        garbage?;
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
        let object_pairs = self
            .store
            .media_objects_for_transfer(transfer_id)?
            .into_iter()
            .map(|object| {
                let state = if object.chunk_count == 0 {
                    MediaTransferState::Complete
                } else {
                    all_empty = false;
                    MediaTransferState::Queued
                };
                let after = media_object_with_state(&object, state);
                (object, after)
            })
            .collect::<Vec<_>>();
        let mut transfer_after = transfer.clone();
        transfer_after.state = if all_empty {
            MediaTransferState::Complete
        } else {
            MediaTransferState::Queued
        };
        transfer_after.updated_at = now;
        self.commit_attachment_state(&transfer, &transfer_after, &object_pairs, &[], rng)?;
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
        let object_pairs = if transfer.direction == MediaDirection::Inbound {
            self.store
                .media_objects_for_transfer(transfer_id)?
                .into_iter()
                .filter(|object| object.state != MediaTransferState::Complete)
                .map(|object| {
                    let after = media_object_with_state(&object, MediaTransferState::Paused);
                    (object, after)
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let mut transfer_after = transfer.clone();
        transfer_after.state = MediaTransferState::Paused;
        transfer_after.updated_at = now;
        self.commit_attachment_state(&transfer, &transfer_after, &object_pairs, &[], rng)?;
        self.attachment_request_at.remove(transfer_id);
        self.attachment_request_target.remove(transfer_id);
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
        let object_pairs = if transfer.direction == MediaDirection::Inbound {
            self.store
                .media_objects_for_transfer(transfer_id)?
                .into_iter()
                .filter(|object| object.state != MediaTransferState::Complete)
                .map(|object| {
                    let after = media_object_with_state(&object, MediaTransferState::Queued);
                    (object, after)
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let state = if transfer.direction == MediaDirection::Outbound
            && self.attachment_manifest_was_queued(&transfer)?
        {
            MediaTransferState::Transferring
        } else {
            MediaTransferState::Queued
        };
        let mut transfer_after = transfer.clone();
        transfer_after.state = state;
        transfer_after.updated_at = now;
        self.commit_attachment_state(&transfer, &transfer_after, &object_pairs, &[], rng)?;
        self.attachment_request_at.remove(transfer_id);
        self.attachment_request_target.remove(transfer_id);
        self.emit_attachment_update(transfer_id)
    }

    pub(crate) fn prepare_pairwise_attachment_offer(
        &self,
        peer: [u8; 32],
        content_id: [u8; 16],
        manifest: &AttachmentManifest<'_>,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(MediaTransferRecord, Vec<MediaObjectRecord>)> {
        let mut transfer_id = [0u8; 16];
        rng.fill_bytes(&mut transfer_id);
        let me = self.account.ed;
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
        let mut objects = Vec::new();
        for descriptor in core::iter::once(&manifest.primary).chain(manifest.preview.as_ref()) {
            let mut local_id = [0u8; 16];
            rng.fill_bytes(&mut local_id);
            objects.push(MediaObjectRecord {
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
            });
        }
        Ok((transfer, objects))
    }

    pub(crate) fn prepare_group_attachment_offer(
        &self,
        offer: GroupAttachmentOffer,
        content_id: [u8; 16],
        manifest: &AttachmentManifest<'_>,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(MediaTransferRecord, Vec<MediaObjectRecord>)> {
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
        let mut objects = Vec::new();
        for descriptor in core::iter::once(&manifest.primary).chain(manifest.preview.as_ref()) {
            let mut local_id = [0u8; 16];
            rng.fill_bytes(&mut local_id);
            objects.push(MediaObjectRecord {
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
            });
        }
        Ok((transfer, objects))
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
                        && transfer.state == MediaTransferState::Queued
                        && self
                            .store
                            .media_objects_for_transfer(&transfer.local_id)?
                            .iter()
                            .all(|object| object.state == MediaTransferState::Complete) =>
                {
                    if self.queue_pairwise_attachment_manifest(transfer, now, rng)? {
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
                    let mut padded = Vec::new();
                    let verified_before =
                        self.verified_attachment_chunk_count(&transfer.local_id)?;
                    let mut requested_chunks = 0usize;
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
                            padded.extend(Self::encode_attachment_bulk_records(&[&complete])?);
                            continue;
                        }
                        let ranges = missing_ranges(&object);
                        if ranges.is_empty() {
                            continue;
                        }
                        requested_chunks = requested_chunks.saturating_add(
                            missing_chunk_count(&ranges).min(MAX_CHUNKS_PER_REQUEST),
                        );
                        let role = role_from_u8(object.role)?;
                        let record = self.bulk_record(
                            transfer,
                            object.object_id,
                            AttachmentBulkOperation::RequestMissing { role, ranges },
                        )?;
                        padded.extend(Self::encode_attachment_bulk_records(&[&record])?);
                    }
                    if !padded.is_empty() {
                        let mut transfer_after = transfer.clone();
                        transfer_after.state = if self
                            .store
                            .media_objects_for_transfer(&transfer.local_id)?
                            .iter()
                            .all(|object| object.state == MediaTransferState::Complete)
                        {
                            MediaTransferState::Complete
                        } else {
                            MediaTransferState::Transferring
                        };
                        let transfer_transition =
                            (transfer != &transfer_after).then_some(MediaTransferTransition {
                                before: transfer,
                                after: &transfer_after,
                            });
                        self.queue_attachment_padded_to_account(
                            &transfer.peer,
                            &padded,
                            transfer_transition.as_slice(),
                            &[],
                            &[],
                            now,
                            rng,
                        )?;
                        if requested_chunks == 0 {
                            self.attachment_request_target.remove(&transfer.local_id);
                        } else {
                            self.attachment_request_target.insert(
                                transfer.local_id,
                                verified_before.saturating_add(requested_chunks),
                            );
                        }
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
                let mut transfer_after = transfer.clone();
                transfer_after.updated_at = 0;
                let transition = MediaTransferTransition {
                    before: transfer,
                    after: &transfer_after,
                };
                self.queue_attachment_bulk_records_to_account(
                    &transfer.peer,
                    &[&terminal],
                    &[transition],
                    &[],
                    &[],
                    now,
                    rng,
                )?;
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
                    || !self
                        .store
                        .media_objects_for_transfer(&transfer.local_id)?
                        .iter()
                        .all(|object| object.state == MediaTransferState::Complete)
                {
                    eligible = false;
                    break;
                }
            }
            if eligible {
                self.queue_group_attachment_manifest(&group, &content_id, now, rng)?;
            }
        }
        Ok(())
    }

    pub(crate) fn apply_attachment_bulk(
        &mut self,
        peer: [u8; 32],
        peer_device: [u8; 32],
        body: &[u8],
        now: u64,
        control: &DeferredControlRecord,
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let DecodedAttachmentBulkRecord::Record(record) = decode_attachment_bulk_record(body)
        else {
            return Ok(false);
        };
        match record.operation {
            AttachmentBulkOperation::RequestMissing { role, ref ranges } => {
                let Some(transfer) = ignore_unknown(self.resolve_bulk_transfer(
                    &record,
                    &peer,
                    MediaDirection::Outbound,
                ))?
                else {
                    return Ok(false);
                };
                if transfer.state == MediaTransferState::Paused {
                    return Ok(false);
                }
                let Some(object) =
                    ignore_unknown(self.resolve_bulk_object(&transfer, record.object_id, role))?
                else {
                    return Ok(false);
                };
                if validate_missing_ranges(ranges, object.chunk_count).is_err() {
                    return Ok(false);
                }
                let mut served = 0usize;
                let mut chunks = Vec::new();
                'ranges: for range in ranges {
                    for index in range.start..range.start + range.count {
                        if served == MAX_CHUNKS_PER_REQUEST {
                            break 'ranges;
                        }
                        let sealed = self.store.read_media_chunk(&object.local_id, index)?;
                        chunks.push((index, sealed));
                        served += 1;
                    }
                }
                if chunks.is_empty() {
                    return Ok(false);
                }
                let records = chunks
                    .iter()
                    .map(|(index, sealed)| {
                        self.bulk_record(
                            &transfer,
                            object.object_id,
                            AttachmentBulkOperation::Chunk {
                                role,
                                index: *index,
                                sealed_chunk: sealed,
                            },
                        )
                    })
                    .collect::<Result<Vec<_>>>()?;
                let record_refs = records.iter().collect::<Vec<_>>();
                let mut transfer_after = transfer.clone();
                transfer_after.state = MediaTransferState::Transferring;
                transfer_after.updated_at = now;
                let transfer_transition =
                    (transfer != transfer_after).then_some(MediaTransferTransition {
                        before: &transfer,
                        after: &transfer_after,
                    });
                self.queue_attachment_bulk_records(
                    &[peer_device],
                    &record_refs,
                    transfer_transition.as_slice(),
                    &[],
                    core::slice::from_ref(control),
                    now,
                    rng,
                )?;
                self.emit_attachment_update(&transfer.local_id)?;
                Ok(true)
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
                    return Ok(false);
                };
                let Some(object) =
                    ignore_unknown(self.resolve_bulk_object(&transfer, record.object_id, role))?
                else {
                    return Ok(false);
                };
                if index >= object.chunk_count {
                    return Ok(false);
                }
                let manifest = self.load_manifest(&transfer)?;
                let Some(manifest_object) = manifest.objects.iter().find(|candidate| {
                    candidate.object_id == object.object_id && candidate.role == role
                }) else {
                    return Ok(false);
                };
                let context = self.chunk_context(&transfer, manifest_object);
                if open_attachment_chunk(&manifest.attachment_key, &context, index, sealed_chunk)
                    .is_err()
                {
                    self.finish_attachment_from_control(
                        &transfer,
                        object.object_id,
                        MediaTransferState::Corrupt,
                        Some(AttachmentBulkOperation::Cancel(AttachmentReason::Corrupt)),
                        peer_device,
                        control,
                        now,
                        rng,
                    )?;
                    return Ok(true);
                }
                let staged =
                    match self
                        .store
                        .stage_media_chunk(&object.local_id, index, sealed_chunk, rng)
                    {
                        Ok(staged) => staged,
                        Err(StoreError::MediaQuota) => {
                            self.finish_attachment_from_control(
                                &transfer,
                                object.object_id,
                                MediaTransferState::Rejected,
                                Some(AttachmentBulkOperation::Reject(AttachmentReason::Quota)),
                                peer_device,
                                control,
                                now,
                                rng,
                            )?;
                            return Ok(true);
                        }
                        Err(StoreError::LowStorage) => {
                            self.finish_attachment_from_control(
                                &transfer,
                                object.object_id,
                                MediaTransferState::Rejected,
                                Some(AttachmentBulkOperation::Reject(
                                    AttachmentReason::LowStorage,
                                )),
                                peer_device,
                                control,
                                now,
                                rng,
                            )?;
                            return Ok(true);
                        }
                        Err(StoreError::MediaState) => {
                            self.finish_attachment_from_control(
                                &transfer,
                                object.object_id,
                                MediaTransferState::Corrupt,
                                Some(AttachmentBulkOperation::Cancel(AttachmentReason::Corrupt)),
                                peer_device,
                                control,
                                now,
                                rng,
                            )?;
                            return Ok(true);
                        }
                        Err(error) => return Err(error.into()),
                    };
                let mut object_after = staged.after;
                let mut complete_response = None;
                if object_after.chunk_addresses.iter().all(Option::is_some) {
                    let mut hasher = blake3::Hasher::new();
                    for chunk_index in 0..object_after.chunk_count {
                        let sealed = self
                            .store
                            .read_media_chunk_from_record(&object_after, chunk_index)?;
                        let plain = Zeroizing::new(open_attachment_chunk(
                            &manifest.attachment_key,
                            &context,
                            chunk_index,
                            &sealed,
                        )?);
                        hasher.update(&plain);
                    }
                    let verified_hash = *hasher.finalize().as_bytes();
                    if verified_hash != object_after.content_hash {
                        self.finish_attachment_from_control(
                            &transfer,
                            object_after.object_id,
                            MediaTransferState::Corrupt,
                            Some(AttachmentBulkOperation::Cancel(AttachmentReason::Corrupt)),
                            peer_device,
                            control,
                            now,
                            rng,
                        )?;
                        return Ok(true);
                    }
                    object_after.state = MediaTransferState::Complete;
                    complete_response = Some(AttachmentBulkOperation::Complete {
                        role,
                        content_hash: verified_hash,
                    });
                }
                let all_complete = object_after.state == MediaTransferState::Complete
                    && self
                        .store
                        .media_objects_for_transfer(&transfer.local_id)?
                        .iter()
                        .filter(|candidate| candidate.local_id != object_after.local_id)
                        .all(|candidate| candidate.state == MediaTransferState::Complete);
                let mut transfer_after = transfer.clone();
                transfer_after.state = if all_complete {
                    MediaTransferState::Complete
                } else {
                    MediaTransferState::Transferring
                };
                transfer_after.updated_at = now;
                let object_pairs = (staged.before != object_after)
                    .then_some((staged.before, object_after))
                    .into_iter()
                    .collect::<Vec<_>>();
                if let Some(operation) = complete_response {
                    let complete = self.bulk_record(&transfer, record.object_id, operation)?;
                    let transfer_transition =
                        (transfer != transfer_after).then_some(MediaTransferTransition {
                            before: &transfer,
                            after: &transfer_after,
                        });
                    let object_transitions = object_pairs
                        .iter()
                        .map(|(before, after)| MediaObjectTransition { before, after })
                        .collect::<Vec<_>>();
                    self.queue_attachment_bulk_records(
                        &[peer_device],
                        &[&complete],
                        transfer_transition.as_slice(),
                        &object_transitions,
                        core::slice::from_ref(control),
                        now,
                        rng,
                    )?;
                } else {
                    self.commit_attachment_state(
                        &transfer,
                        &transfer_after,
                        &object_pairs,
                        core::slice::from_ref(control),
                        rng,
                    )?;
                }
                if let Some(target) = self
                    .attachment_request_target
                    .get(&transfer.local_id)
                    .copied()
                {
                    let verified = self.verified_attachment_chunk_count(&transfer.local_id)?;
                    if verified >= target {
                        self.attachment_request_at.remove(&transfer.local_id);
                        self.attachment_request_target.remove(&transfer.local_id);
                    }
                }
                self.emit_attachment_update(&transfer.local_id)?;
                Ok(true)
            }
            AttachmentBulkOperation::Complete { role, content_hash } => {
                let Some(transfer) = ignore_unknown(self.resolve_bulk_transfer(
                    &record,
                    &peer,
                    MediaDirection::Outbound,
                ))?
                else {
                    return Ok(false);
                };
                let Some(object) =
                    ignore_unknown(self.resolve_bulk_object(&transfer, record.object_id, role))?
                else {
                    return Ok(false);
                };
                if object.content_hash != content_hash {
                    return Ok(false);
                }
                // Completion acknowledgements can cross an explicit local
                // terminal decision in flight. A delayed acknowledgement
                // confirms remote receipt, but must not resurrect work the
                // user cancelled/rejected or that failed integrity locally.
                if attachment_state_is_negative_terminal(transfer.state) {
                    return Ok(false);
                }
                let mut transfer_after = transfer.clone();
                transfer_after.state = MediaTransferState::Complete;
                transfer_after.updated_at = now;
                self.commit_attachment_state(
                    &transfer,
                    &transfer_after,
                    &[],
                    core::slice::from_ref(control),
                    rng,
                )?;
                self.emit_attachment_update(&transfer.local_id)?;
                Ok(true)
            }
            AttachmentBulkOperation::Cancel(_) => {
                let Some(transfer) =
                    ignore_unknown(self.resolve_bulk_transfer_any_direction(&record, &peer))?
                else {
                    return Ok(false);
                };
                if attachment_state_is_negative_terminal(transfer.state) {
                    return Ok(false);
                }
                if !self
                    .store
                    .media_objects_for_transfer(&transfer.local_id)?
                    .iter()
                    .any(|object| object.object_id == record.object_id)
                {
                    return Ok(false);
                }
                self.finish_attachment_from_control(
                    &transfer,
                    record.object_id,
                    MediaTransferState::Cancelled,
                    None,
                    peer_device,
                    control,
                    now,
                    rng,
                )?;
                Ok(true)
            }
            AttachmentBulkOperation::Reject(_) => {
                let Some(transfer) = ignore_unknown(self.resolve_bulk_transfer(
                    &record,
                    &peer,
                    MediaDirection::Outbound,
                ))?
                else {
                    return Ok(false);
                };
                if attachment_state_is_negative_terminal(transfer.state) {
                    return Ok(false);
                }
                if !self
                    .store
                    .media_objects_for_transfer(&transfer.local_id)?
                    .iter()
                    .any(|object| object.object_id == record.object_id)
                {
                    return Ok(false);
                }
                self.finish_attachment_from_control(
                    &transfer,
                    record.object_id,
                    MediaTransferState::Rejected,
                    None,
                    peer_device,
                    control,
                    now,
                    rng,
                )?;
                Ok(true)
            }
        }
    }

    pub(crate) fn peer_supports_attachment(&self, peer: &[u8; 32]) -> Result<bool> {
        self.peer_supports_kind(peer, CONTENT_KIND_ATTACHMENT)
    }

    fn queue_pairwise_attachment_manifest(
        &mut self,
        transfer: &MediaTransferRecord,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<bool> {
        let Some(message_before) =
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
        let mut routes = self.store.contact_devices_for(&transfer.peer)?;
        if routes.is_empty() {
            routes.push(kult_store::ContactDeviceRecord {
                account: transfer.peer,
                device: transfer.peer,
                name: None,
                certificate: Vec::new(),
                authority: Vec::new(),
                bundle: Vec::new(),
                hints: Vec::new(),
                introduction_capability: None,
                introduction_generation: 0,
                manifest_generation: 0,
                manifest_state_id: [0u8; 32],
                last_seen: now,
                revoked_at: None,
                revoked_after_counter: None,
            });
        }
        routes.sort_by_key(|endpoint| endpoint.device);
        routes.dedup_by_key(|endpoint| endpoint.device);
        let deliveries = self
            .store
            .message_device_deliveries(&transfer.manifest_content_id)?;
        if routes.iter().any(|endpoint| {
            !deliveries
                .iter()
                .any(|delivery| delivery.device == endpoint.device && delivery.wire_id.is_some())
                && !self.sessions.contains_key(&endpoint.device)
        }) {
            return Ok(false);
        }

        let padded = pad(&message_before.body)?;
        let retention = attachment_ephemeral_retention(&message_before.body);
        let mut message_after = message_before.clone();
        let mut prepared = Vec::new();
        let mut queue = Vec::new();
        let mut new_deliveries = Vec::new();
        let mut delivery_pairs = Vec::new();
        for endpoint in routes {
            if deliveries
                .iter()
                .any(|delivery| delivery.device == endpoint.device && delivery.wire_id.is_some())
            {
                continue;
            }
            let route = endpoint.device;
            let before = self
                .sessions
                .get(&route)
                .cloned()
                .ok_or(NodeError::NoSession)?;
            let mut after = before.clone();
            let ratchet = self.candidate_encrypt(&mut after, rng, now, &padded)?;
            let token = delivery_token(
                &MailboxKey::from_bytes(*after.mailbox_key()),
                epoch_day(now),
                &route,
            );
            let envelope = match retention {
                Some(deadline) => Envelope::new_retained(
                    EnvelopeKind::Message,
                    token,
                    deadline,
                    ratchet.encode(),
                )?,
                None => Envelope::new(EnvelopeKind::Message, token, ratchet.encode()),
            };
            let wire_id = envelope.content_id();
            if message_after.wire_id.is_none() {
                message_after.wire_id = Some(wire_id);
            }
            let delivery_after = MessageDeviceDeliveryRecord {
                message: message_before.id,
                account: transfer.peer,
                device: route,
                wire_id: Some(wire_id),
                state: DeliveryState::Queued,
            };
            if let Some(before_delivery) =
                deliveries.iter().find(|delivery| delivery.device == route)
            {
                delivery_pairs.push((before_delivery.clone(), delivery_after));
            } else {
                new_deliveries.push(delivery_after);
            }
            queue.push(QueueItem {
                peer: route,
                msg_id: Some(message_before.id),
                group_msg_id: None,
                class: QueueClass::Bulk,
                created_at: now,
                attempts: 0,
                next_attempt_at: now,
                envelope: envelope.clone(),
            });
            prepared.push((route, before, after));
        }
        if prepared.is_empty() {
            if message_before.wire_id.is_none() {
                return Ok(false);
            }
            let mut transfer_after = transfer.clone();
            transfer_after.state = MediaTransferState::Transferring;
            transfer_after.updated_at = now;
            self.commit_attachment_state(transfer, &transfer_after, &[], &[], rng)?;
            return Ok(true);
        }
        let session_transitions = prepared
            .iter()
            .map(|(route, before, after)| SessionTransition {
                peer_device: *route,
                before: Some(before),
                after,
            })
            .collect::<Vec<_>>();
        let delivery_updates = delivery_pairs
            .iter()
            .map(|(before, after)| kult_store::DeliveryTransition { before, after })
            .collect::<Vec<_>>();
        let mut transfer_after = transfer.clone();
        transfer_after.state = MediaTransferState::Transferring;
        transfer_after.updated_at = now;
        let media_transfers = [MediaTransferTransition {
            before: transfer,
            after: &transfer_after,
        }];
        self.store.commit_plan(
            CommitPlan::PairwiseSend(PairwiseSendPlan {
                sessions: &session_transitions,
                message: None,
                message_update: Some(MessageTransition {
                    before: &message_before,
                    after: &message_after,
                }),
                deliveries: &new_deliveries,
                delivery_updates: &delivery_updates,
                queue: &queue,
                groups: &[],
                authorities: &[],
                scheduled: None,
                clear_capabilities: &[],
                clear_reset_markers: &[],
                ephemeral: None,
                media_transfers: &media_transfers,
                media_objects: &[],
                delete_controls: &[],
                presentation_changed: false,
            }),
            rng,
        )?;
        self.before_memory_replacement()?;
        for (route, _, after) in prepared {
            self.sessions.insert(route, after);
        }
        self.after_memory_replacement()?;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)] // exact control and durable consequence boundary
    fn queue_attachment_bulk_records_to_account(
        &mut self,
        account: &[u8; 32],
        records: &[&AttachmentBulkRecord<'_>],
        media_transfers: &[MediaTransferTransition<'_>],
        media_objects: &[MediaObjectTransition<'_>],
        delete_controls: &[DeferredControlRecord],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let padded = Self::encode_attachment_bulk_records(records)?;
        self.queue_attachment_padded_to_account(
            account,
            &padded,
            media_transfers,
            media_objects,
            delete_controls,
            now,
            rng,
        )
    }

    #[allow(clippy::too_many_arguments)] // exact control and durable consequence boundary
    fn queue_attachment_padded_to_account(
        &mut self,
        account: &[u8; 32],
        padded: &[Vec<u8>],
        media_transfers: &[MediaTransferTransition<'_>],
        media_objects: &[MediaObjectTransition<'_>],
        delete_controls: &[DeferredControlRecord],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let endpoints = self.store.contact_devices_for(account)?;
        let devices = if endpoints.is_empty() {
            vec![*account]
        } else {
            endpoints
                .iter()
                .map(|endpoint| endpoint.device)
                .collect::<Vec<_>>()
        };
        if devices
            .iter()
            .any(|device| !self.sessions.contains_key(device))
        {
            return Err(NodeError::NoSession);
        }
        self.queue_attachment_padded(
            &devices,
            padded,
            media_transfers,
            media_objects,
            delete_controls,
            now,
            rng,
        )
    }

    #[allow(clippy::too_many_arguments)] // exact control and durable consequence boundary
    fn queue_attachment_bulk_records(
        &mut self,
        devices: &[[u8; 32]],
        records: &[&AttachmentBulkRecord<'_>],
        media_transfers: &[MediaTransferTransition<'_>],
        media_objects: &[MediaObjectTransition<'_>],
        delete_controls: &[DeferredControlRecord],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let padded = Self::encode_attachment_bulk_records(records)?;
        self.queue_attachment_padded(
            devices,
            &padded,
            media_transfers,
            media_objects,
            delete_controls,
            now,
            rng,
        )
    }

    fn encode_attachment_bulk_records(
        records: &[&AttachmentBulkRecord<'_>],
    ) -> Result<Vec<Vec<u8>>> {
        records
            .iter()
            .map(|record| -> Result<Vec<u8>> {
                let payload = encode_attachment_bulk_record(record)?;
                Ok(pad_to_minimum(&payload, BULK_CONTROL_PADDING_FLOOR)?)
            })
            .collect()
    }

    #[allow(clippy::too_many_arguments)] // exact control and durable consequence boundary
    fn queue_attachment_padded(
        &mut self,
        devices: &[[u8; 32]],
        padded: &[Vec<u8>],
        media_transfers: &[MediaTransferTransition<'_>],
        media_objects: &[MediaObjectTransition<'_>],
        delete_controls: &[DeferredControlRecord],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let payloads = padded.iter().map(Vec::as_slice).collect::<Vec<_>>();
        self.commit_pairwise_payloads_with_effects(
            devices,
            &payloads,
            EnvelopeKind::Receipt,
            QueueClass::Bulk,
            None,
            media_transfers,
            media_objects,
            delete_controls,
            now,
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

    fn commit_attachment_state(
        &mut self,
        transfer_before: &MediaTransferRecord,
        transfer_after: &MediaTransferRecord,
        object_pairs: &[(MediaObjectRecord, MediaObjectRecord)],
        delete_controls: &[DeferredControlRecord],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let transfer = (transfer_before != transfer_after).then_some(MediaTransferTransition {
            before: transfer_before,
            after: transfer_after,
        });
        let objects = object_pairs
            .iter()
            .filter(|(before, after)| before != after)
            .map(|(before, after)| MediaObjectTransition { before, after })
            .collect::<Vec<_>>();
        let receipt = self.store.commit_plan(
            CommitPlan::AttachmentState(AttachmentStatePlan {
                media_transfers: transfer.as_slice(),
                media_objects: &objects,
                delete_controls,
                presentation_changed: true,
            }),
            rng,
        )?;
        self.accept_commit_receipt(receipt, []);
        Ok(())
    }

    fn require_attachment(&self, transfer_id: &[u8; 16]) -> Result<MediaTransferRecord> {
        match self.store.get_media_transfer(transfer_id)? {
            Some(MediaRecord::Available(transfer)) => Ok(transfer),
            _ => Err(NodeError::UnknownAttachment),
        }
    }

    fn attachment_info(&self, transfer: &MediaTransferRecord) -> Result<AttachmentInfo> {
        let ephemeral = self.store.ephemeral_records()?.into_iter().find(|record| {
            record.mode == EphemeralMode::ViewOnceAttachment
                && record.transfer_ids.contains(&transfer.local_id)
        });
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
            view_once: ephemeral.is_some(),
            expires_at: ephemeral.as_ref().map(|record| record.expires_at),
            consumed: ephemeral
                .as_ref()
                .is_some_and(|record| record.state != EphemeralState::Active),
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
        let object_pairs = if transfer.direction == MediaDirection::Inbound
            || state == MediaTransferState::Corrupt
        {
            self.store
                .media_objects_for_transfer(&transfer.local_id)?
                .into_iter()
                .map(|object| {
                    let after = media_object_with_state(&object, state);
                    (object, after)
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let mut transfer_after = transfer.clone();
        transfer_after.state = state;
        transfer_after.updated_at = if notify_remote { now } else { 0 };
        self.commit_attachment_state(transfer, &transfer_after, &object_pairs, &[], rng)?;
        self.attachment_request_at.remove(&transfer.local_id);
        self.attachment_request_target.remove(&transfer.local_id);
        self.emit_attachment_update(&transfer.local_id)
    }

    #[allow(clippy::too_many_arguments)] // authenticated control, response, and state boundary
    fn finish_attachment_from_control(
        &mut self,
        transfer: &MediaTransferRecord,
        object_id: [u8; 16],
        state: MediaTransferState,
        response: Option<AttachmentBulkOperation<'_>>,
        peer_device: [u8; 32],
        control: &DeferredControlRecord,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let object_pairs = if transfer.direction == MediaDirection::Inbound
            || state == MediaTransferState::Corrupt
        {
            self.store
                .media_objects_for_transfer(&transfer.local_id)?
                .into_iter()
                .map(|object| {
                    let after = media_object_with_state(&object, state);
                    (object, after)
                })
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        let mut transfer_after = transfer.clone();
        transfer_after.state = state;
        transfer_after.updated_at = 0;
        if let Some(operation) = response {
            let record = self.bulk_record(transfer, object_id, operation)?;
            let transfer_transition =
                (transfer != &transfer_after).then_some(MediaTransferTransition {
                    before: transfer,
                    after: &transfer_after,
                });
            let object_transitions = object_pairs
                .iter()
                .filter(|(before, after)| before != after)
                .map(|(before, after)| MediaObjectTransition { before, after })
                .collect::<Vec<_>>();
            self.queue_attachment_bulk_records(
                &[peer_device],
                &[&record],
                transfer_transition.as_slice(),
                &object_transitions,
                core::slice::from_ref(control),
                now,
                rng,
            )?;
        } else {
            self.commit_attachment_state(
                transfer,
                &transfer_after,
                &object_pairs,
                core::slice::from_ref(control),
                rng,
            )?;
        }
        self.attachment_request_at.remove(&transfer.local_id);
        self.attachment_request_target.remove(&transfer.local_id);
        if !object_pairs.is_empty() {
            self.store.collect_media_garbage()?;
        }
        self.emit_attachment_update(&transfer.local_id)
    }

    fn verified_attachment_chunk_count(&self, transfer_id: &[u8; 16]) -> Result<usize> {
        Ok(self
            .store
            .media_objects_for_transfer(transfer_id)?
            .iter()
            .map(|object| {
                object
                    .chunk_addresses
                    .iter()
                    .filter(|address| address.is_some())
                    .count()
            })
            .sum())
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
        let manifest = match decode_content(&body) {
            DecodedContent::Attachment { manifest, .. }
            | DecodedContent::Ephemeral {
                ephemeral: Ephemeral::ViewOnceAttachment { manifest, .. },
                ..
            } => manifest,
            _ => return Err(NodeError::InvalidAttachment),
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

fn missing_chunk_count(ranges: &[MissingRange]) -> usize {
    ranges
        .iter()
        .map(|range| range.count as usize)
        .fold(0usize, usize::saturating_add)
}

fn attachment_ephemeral_retention(body: &[u8]) -> Option<u64> {
    match decode_content(body) {
        DecodedContent::Ephemeral {
            ephemeral:
                Ephemeral::ViewOnceAttachment {
                    retention_until, ..
                },
            ..
        } => Some(retention_until),
        _ => None,
    }
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
        let control = DeferredControlRecord {
            content_id: [5; 16],
            peer: [2; 32],
            peer_device: [2; 32],
            kind: kult_store::DeferredControlKind::AttachmentBulk,
            body: encoded.clone(),
            received_at: 1_800_000_000,
        };
        assert!(!node
            .apply_attachment_bulk(
                [2; 32],
                [2; 32],
                &encoded,
                1_800_000_000,
                &control,
                &mut rng,
            )
            .unwrap());
        assert!(node.attachments().unwrap().is_empty());
        assert!(node.drain_events().is_empty());
    }
}
