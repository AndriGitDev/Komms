//! Bounded typed transactions for protocol-state transitions (ADR-0028).

use std::collections::HashSet;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use kult_crypto::Session;
use kult_protocol::{CapabilityControl, Envelope, EnvelopeKind};

use crate::{
    decode_exact, store_v2, ContactDeviceRecord, ContactRecord, DeliveryState, Direction,
    EphemeralRecord, EphemeralState, GroupMessageRecord, GroupRecord, MediaObjectRecord,
    MediaTransferRecord, MessageDeviceDeliveryRecord, MessageRecord, QueueItem, Result,
    ScheduledMessageRecord, Store, StoreError,
};

/// Maximum logical durable mutations accepted by one typed commit plan.
pub const MAX_COMMIT_MUTATIONS: usize = 512;
/// Maximum physical devices in one pairwise fan-out.
pub const MAX_PAIRWISE_COMMIT_DEVICES: usize = 8;
/// Maximum queue rows created by one protocol transition.
pub const MAX_COMMIT_QUEUE_ROWS: usize = 128;
/// Maximum exact maintenance transitions applied in one transaction.
pub const MAX_MAINTENANCE_TRANSITIONS: usize = 256;
/// Maximum authenticated control records retained for post-commit work.
pub const MAX_DEFERRED_CONTROLS: usize = 512;

/// Kind of authenticated pairwise control retained for idempotent follow-up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeferredControlKind {
    /// Attachment bulk request, chunk, or terminal response.
    AttachmentBulk,
    /// Pairwise-ratchet-protected group control.
    GroupControl,
}

/// Immutable accepted control state whose external work occurs after commit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeferredControlRecord {
    /// Envelope content id and durable equality key.
    pub content_id: [u8; 16],
    /// Stable account identity that authenticated the control.
    pub peer: [u8; 32],
    /// Exact physical session route that authenticated the control.
    pub peer_device: [u8; 32],
    /// Typed follow-up behavior.
    pub kind: DeferredControlKind,
    /// Exact decrypted authenticated control bytes.
    pub body: Vec<u8>,
    /// Local acceptance time.
    pub received_at: u64,
}

/// A durable session replacement tied to its exact prior value.
pub struct SessionTransition<'a> {
    /// Exact physical-device route.
    pub peer_device: [u8; 32],
    /// Durable session expected before the transaction, or `None` for a new route.
    pub before: Option<&'a Session>,
    /// Candidate session produced without mutating live runtime state.
    pub after: &'a Session,
}

/// One deferred-inbox row that may be removed only with its named envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingDelete {
    /// Stable pending row sequence.
    pub sequence: i64,
    /// Exact envelope content id expected in that row.
    pub content_id: [u8; 16],
}

/// One outbound row that may be removed only with its named envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueueDelete {
    /// Stable outbound row sequence.
    pub sequence: i64,
    /// Exact envelope content id expected in that row.
    pub content_id: [u8; 16],
}

/// An exact in-place outbound queue update.
pub struct QueueTransition<'a> {
    /// Stable outbound row sequence.
    pub sequence: i64,
    /// Exact durable value expected before the transaction.
    pub before: &'a QueueItem,
    /// Replacement scheduling or delivery value.
    pub after: &'a QueueItem,
}

/// An exact pairwise history update.
pub struct MessageTransition<'a> {
    /// Exact durable value expected before the transaction.
    pub before: &'a MessageRecord,
    /// Replacement value with the same immutable identity.
    pub after: &'a MessageRecord,
}

/// One pairwise history row removed only after a tombstone is committed.
pub struct MessageDelete<'a> {
    /// Exact durable value expected before deletion.
    pub before: &'a MessageRecord,
}

/// One group history row removed only after a tombstone is committed.
pub struct GroupMessageDelete<'a> {
    /// Exact durable value expected before deletion.
    pub before: &'a GroupMessageRecord,
}

/// An exact per-device delivery-state update.
pub struct DeliveryTransition<'a> {
    /// Exact durable value expected before the transaction.
    pub before: &'a MessageDeviceDeliveryRecord,
    /// Replacement delivery value with the same identity.
    pub after: &'a MessageDeviceDeliveryRecord,
}

/// An exact group-state update.
pub struct GroupTransition<'a> {
    /// Exact durable value expected before the transaction.
    pub before: &'a GroupRecord,
    /// Replacement value with the same group id.
    pub after: &'a GroupRecord,
}

/// An exact group-history update.
pub struct GroupMessageTransition<'a> {
    /// Exact durable value expected before the transaction.
    pub before: &'a GroupMessageRecord,
    /// Replacement value with the same immutable identity.
    pub after: &'a GroupMessageRecord,
}

/// An exact ephemeral marker update.
pub struct EphemeralTransition<'a> {
    /// Existing marker, or `None` when the transition creates it.
    pub before: Option<&'a EphemeralRecord>,
    /// Resulting active marker or tombstone.
    pub after: &'a EphemeralRecord,
}

/// Exact media rows removed after their semantic tombstone is durable.
pub struct MediaDelete<'a> {
    /// Transfer id whose metadata is removed.
    pub transfer_id: [u8; 16],
    /// Exact local object ids removed before the transfer row.
    pub object_ids: &'a [[u8; 16]],
}

/// One exact contact endpoint removed by an authenticated manifest transition.
pub struct ContactDeviceDelete<'a> {
    /// Exact durable endpoint expected before deletion.
    pub before: &'a ContactDeviceRecord,
}

/// Complete durable consequences of one pairwise send.
pub struct PairwiseSendPlan<'a> {
    /// Every detached sending-session candidate advanced by the fan-out.
    pub sessions: &'a [SessionTransition<'a>],
    /// Immutable local history, absent for protocol control traffic.
    pub message: Option<&'a MessageRecord>,
    /// Exact history update when a previously unavailable device becomes usable.
    pub message_update: Option<MessageTransition<'a>>,
    /// Honest per-device delivery rows created with new history.
    pub deliveries: &'a [MessageDeviceDeliveryRecord],
    /// Exact delivery updates for a previously retained history row.
    pub delivery_updates: &'a [DeliveryTransition<'a>],
    /// Every ciphertext produced by the candidate sessions.
    pub queue: &'a [QueueItem],
    /// Exact scheduled record consumed by activation, when applicable.
    pub scheduled: Option<&'a ScheduledMessageRecord>,
    /// Session-bound capability snapshots invalidated by new handshakes.
    pub clear_capabilities: &'a [[u8; 32]],
    /// Exact restore markers consumed by successful reset handshakes.
    pub clear_reset_markers: &'a [[u8; 32]],
    /// Optional local ephemeral marker created with history.
    pub ephemeral: Option<&'a EphemeralRecord>,
    /// Whether presentation must be recoverable after commit.
    pub presentation_changed: bool,
}

/// Complete durable consequences of one pairwise message/control receive.
pub struct PairwiseReceivePlan<'a> {
    /// Detached receiving candidate, including an optional receipt send step.
    pub session: SessionTransition<'a>,
    /// Accepted immutable history row, if this content creates one.
    pub message: Option<&'a MessageRecord>,
    /// Optional local ephemeral marker or tombstone.
    pub ephemeral: Option<&'a EphemeralRecord>,
    /// Attachment offer transfer metadata created by accepted content.
    pub media_transfers: &'a [MediaTransferRecord],
    /// Attachment offer object metadata created by accepted content.
    pub media_objects: &'a [MediaObjectRecord],
    /// Authenticated capability snapshot carried as pairwise control.
    pub capabilities: Option<&'a CapabilityControl>,
    /// Outbound receipt/control ciphertext produced by the same candidate.
    pub queue: &'a [QueueItem],
    /// Authenticated envelope content id used for replay absorption.
    pub content_id: [u8; 16],
    /// Local receive time retained with an optional duplicate-receipt route.
    pub received_at: u64,
    /// Whether duplicate delivery should replay a receipt to this route.
    pub receipt_replay: bool,
    /// Exact deferred source row, when this input came from the durable inbox.
    pub source_pending: Option<PendingDelete>,
    /// Whether presentation must be recoverable after commit.
    pub presentation_changed: bool,
}

/// Exact prekey-vault replacement performed by an inbound handshake.
pub struct PrekeyTransition<'a> {
    /// Encoded durable vault expected before the transaction.
    pub before: &'a [u8],
    /// Encoded candidate vault after one-time-prekey consumption.
    pub after: &'a [u8],
}

/// Complete durable consequences of accepting one inbound handshake.
pub struct HandshakeReceivePlan<'a> {
    /// Optional one-time-prekey consumption.
    pub prekeys: Option<PrekeyTransition<'a>>,
    /// Newly established detached session.
    pub session: SessionTransition<'a>,
    /// Contact stub or authenticated contact update.
    pub contact: &'a ContactRecord,
    /// Authenticated physical-device endpoint updates.
    pub devices: &'a [ContactDeviceRecord],
    /// Superseded legacy endpoint rows removed by the same manifest.
    pub delete_devices: &'a [ContactDeviceDelete<'a>],
    /// Superseded or revoked sessions removed by the same manifest.
    pub delete_sessions: &'a [[u8; 32]],
    /// Session-bound capability rows removed by the same manifest.
    pub delete_capabilities: &'a [[u8; 32]],
    /// Exact queued envelopes invalidated by revoked/superseded sessions.
    pub delete_queue: &'a [QueueDelete],
    /// Group announce state changed by session establishment.
    pub groups: &'a [GroupTransition<'a>],
    /// Optional accepted anonymous first-flight history.
    pub message: Option<&'a MessageRecord>,
    /// Optional first-flight ephemeral state.
    pub ephemeral: Option<&'a EphemeralRecord>,
    /// Optional first-flight attachment transfer rows.
    pub media_transfers: &'a [MediaTransferRecord],
    /// Optional first-flight attachment object rows.
    pub media_objects: &'a [MediaObjectRecord],
    /// Encrypted receipt generated from the newly established candidate.
    pub queue: &'a [QueueItem],
    /// Handshake envelope content id.
    pub content_id: [u8; 16],
    /// Local receive time retained with duplicate-receipt routing.
    pub received_at: u64,
    /// Whether the accepted first flight needs duplicate receipt replay.
    pub receipt_replay: bool,
    /// Exact deferred source row, when applicable.
    pub source_pending: Option<PendingDelete>,
    /// Whether presentation must be recoverable after commit.
    pub presentation_changed: bool,
}

/// Complete durable consequences of an encrypted receipt/control receive.
pub struct ReceiptReceivePlan<'a> {
    /// Detached session after receive and any response encryption.
    pub session: SessionTransition<'a>,
    /// Exact outbound envelopes acknowledged by the receipt.
    pub delete_queue: &'a [QueueDelete],
    /// Selective retransmissions or control responses created by this receipt.
    pub queue: &'a [QueueItem],
    /// Pairwise aggregate message-state changes.
    pub messages: &'a [MessageTransition<'a>],
    /// Per-device delivery-state changes.
    pub deliveries: &'a [DeliveryTransition<'a>],
    /// Group aggregate delivery changes.
    pub group_messages: &'a [GroupMessageTransition<'a>],
    /// Group pending-announce changes retired by acknowledgements.
    pub groups: &'a [GroupTransition<'a>],
    /// Attachment transfer metadata changes.
    pub media_transfers: &'a [MediaTransferRecord],
    /// Attachment object metadata changes.
    pub media_objects: &'a [MediaObjectRecord],
    /// Authenticated capability snapshot carried by this control.
    pub capabilities: Option<&'a CapabilityControl>,
    /// Immutable control work retained before filesystem or group callbacks.
    pub deferred_control: Option<&'a DeferredControlRecord>,
    /// Receipt envelope content id.
    pub content_id: [u8; 16],
    /// Exact deferred source row, when applicable.
    pub source_pending: Option<PendingDelete>,
    /// Whether presentation must be recoverable after commit.
    pub presentation_changed: bool,
}

/// One bounded expiry, retry, rejection, or acknowledgement transaction.
pub struct MaintenancePlan<'a> {
    /// Terminal envelope ids recorded as seen with their exact pending removal.
    pub seen: &'a [[u8; 16]],
    /// Exact deferred rows removed by terminal handling.
    pub delete_pending: &'a [PendingDelete],
    /// Exact outbound rows removed by expiry or terminal delivery.
    pub delete_queue: &'a [QueueDelete],
    /// Exact outbound scheduling updates.
    pub update_queue: &'a [QueueTransition<'a>],
    /// Duplicate-receipt routes removed after their bounded replay window.
    pub delete_replay: &'a [[u8; 16]],
    /// Pairwise aggregate delivery updates.
    pub messages: &'a [MessageTransition<'a>],
    /// Per-device delivery updates.
    pub deliveries: &'a [DeliveryTransition<'a>],
    /// Group aggregate delivery updates.
    pub group_messages: &'a [GroupMessageTransition<'a>],
    /// Group state updates such as bounded pending announce expiry.
    pub groups: &'a [GroupTransition<'a>],
    /// Ephemeral active-state to tombstone transitions.
    pub ephemeral: &'a [EphemeralTransition<'a>],
    /// Pairwise plaintext rows removed after a tombstone.
    pub delete_messages: &'a [MessageDelete<'a>],
    /// Group plaintext rows removed after a tombstone.
    pub delete_group_messages: &'a [GroupMessageDelete<'a>],
    /// Media metadata removed after a tombstone.
    pub delete_media: &'a [MediaDelete<'a>],
    /// Exact scheduled records removed by terminal cancellation.
    pub delete_scheduled: &'a [ScheduledMessageRecord],
    /// Exact stale ratchet sessions retired by bounded repair.
    pub delete_sessions: &'a [[u8; 32]],
    /// Exact session-bound capability snapshots retired with those sessions.
    pub delete_capabilities: &'a [[u8; 32]],
    /// Exact restore markers consumed by bounded reset upkeep.
    pub clear_reset_markers: &'a [[u8; 32]],
    /// Exact accepted controls acknowledged after idempotent follow-up.
    pub delete_controls: &'a [DeferredControlRecord],
    /// Exact presentation marker acknowledged after event delivery.
    pub acknowledge_presentation: Option<[u8; 16]>,
    /// Whether this maintenance transition itself changes presentation.
    pub presentation_changed: bool,
}

/// The only protocol-state transaction variants exposed by the store.
pub enum CommitPlan<'a> {
    /// Pairwise send.
    PairwiseSend(PairwiseSendPlan<'a>),
    /// Pairwise receive.
    PairwiseReceive(PairwiseReceivePlan<'a>),
    /// Handshake receive.
    HandshakeReceive(HandshakeReceivePlan<'a>),
    /// Receipt or authenticated pairwise control receive.
    ReceiptReceive(ReceiptReceivePlan<'a>),
    /// Bounded maintenance.
    Maintenance(MaintenancePlan<'a>),
}

/// Stable identities returned only after a successful commit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommittedRecordIds {
    /// Pairwise message ids created or updated.
    pub messages: Vec<[u8; 16]>,
    /// Newly appended outbound row sequences.
    pub queue_sequences: Vec<i64>,
}

/// Proof returned after SQLite accepted the complete typed transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitReceipt {
    /// Random identifier for this complete transition.
    pub transaction_id: [u8; 16],
    /// Stable record identities produced by the transaction.
    pub records: CommittedRecordIds,
    /// Marker that must be acknowledged after presentation delivery.
    pub presentation_marker: Option<[u8; 16]>,
    /// Number of bounded logical write statements applied.
    pub statement_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct PresentationMarker {
    transaction_id: [u8; 16],
}

/// Deterministic store commit injection location used by crash-matrix tests.
#[cfg(feature = "test-failpoints")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitFailpoint {
    /// Immediately before `BEGIN IMMEDIATE`.
    BeforeBegin,
    /// Immediately after `BEGIN IMMEDIATE`.
    AfterBegin,
    /// Before the numbered logical write statement, starting at zero.
    BeforeStatement(usize),
    /// After the numbered logical write statement, starting at zero.
    AfterStatement(usize),
    /// Immediately before `COMMIT`.
    BeforeCommit,
    /// Immediately after a successful `COMMIT`.
    AfterCommit,
}

/// Failure class produced by an armed deterministic store failpoint.
#[cfg(feature = "test-failpoints")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitFailure {
    /// Process-interruption equivalent.
    Interrupted,
    /// Disk-full equivalent.
    DiskFull,
    /// Constraint-failure equivalent.
    Constraint,
    /// Duplicate-index equivalent.
    Duplicate,
}

#[cfg(feature = "test-failpoints")]
#[derive(Clone, Copy)]
pub(crate) struct ArmedCommitFailpoint {
    pub(crate) point: CommitFailpoint,
    pub(crate) failure: CommitFailure,
}

impl Store {
    /// Apply one bounded typed protocol transition using `BEGIN IMMEDIATE`.
    pub fn commit_plan(
        &self,
        plan: CommitPlan<'_>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<CommitReceipt> {
        self.validate_commit_plan(&plan)?;
        let presentation_changed = match &plan {
            CommitPlan::PairwiseSend(plan) => plan.presentation_changed,
            CommitPlan::PairwiseReceive(plan) => plan.presentation_changed,
            CommitPlan::HandshakeReceive(plan) => plan.presentation_changed,
            CommitPlan::ReceiptReceive(plan) => plan.presentation_changed,
            CommitPlan::Maintenance(plan) => plan.presentation_changed,
        };
        let mut transaction_id = [0u8; 16];
        rng.fill_bytes(&mut transaction_id);
        if transaction_id == [0u8; 16] {
            transaction_id[0] = 1;
        }

        self.check_commit_failpoint(CommitPoint::BeforeBegin)?;
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let mut writer = CommitWriter {
            store: self,
            rng,
            statement: 0,
            records: CommittedRecordIds::default(),
        };
        let result = (|| {
            writer
                .store
                .check_commit_failpoint(CommitPoint::AfterBegin)?;
            match plan {
                CommitPlan::PairwiseSend(plan) => writer.pairwise_send(&plan)?,
                CommitPlan::PairwiseReceive(plan) => writer.pairwise_receive(&plan)?,
                CommitPlan::HandshakeReceive(plan) => writer.handshake_receive(&plan)?,
                CommitPlan::ReceiptReceive(plan) => writer.receipt_receive(&plan)?,
                CommitPlan::Maintenance(plan) => writer.maintenance(&plan)?,
            }
            if presentation_changed {
                writer.write(|store, rng| {
                    let marker = postcard::to_allocvec(&PresentationMarker { transaction_id })
                        .map_err(|_| StoreError::Serialization)?;
                    store.put_equality::<store_v2::PresentationMarkerRows>(
                        &store_v2::SingletonKey,
                        &marker,
                        store_v2::IndexKeys::none(),
                        rng,
                    )
                })?;
            }
            writer
                .store
                .check_commit_failpoint(CommitPoint::BeforeCommit)?;
            writer.store.conn.execute_batch("COMMIT")?;
            writer
                .store
                .check_commit_failpoint(CommitPoint::AfterCommit)?;
            Ok(CommitReceipt {
                transaction_id,
                records: writer.records,
                presentation_marker: presentation_changed.then_some(transaction_id),
                statement_count: writer.statement,
            })
        })();
        if result.is_err() && !self.conn.is_autocommit() {
            let _ = self.conn.execute_batch("ROLLBACK");
        }
        result
    }

    /// Return the unacknowledged deterministic presentation-resync marker.
    pub fn presentation_resync_marker(&self) -> Result<Option<[u8; 16]>> {
        self.get_equality::<store_v2::PresentationMarkerRows>(&store_v2::SingletonKey)?
            .map(|row| {
                row.verify_key(&store_v2::SingletonKey)?;
                let marker: PresentationMarker = decode_exact(&row.payload)?;
                if marker.transaction_id == [0u8; 16] {
                    return Err(StoreError::LogicalKeyMismatch);
                }
                Ok(marker.transaction_id)
            })
            .transpose()
    }

    /// Validate the bounded presentation marker during store open.
    pub(crate) fn validate_presentation_marker(&self) -> Result<()> {
        self.validate_rows::<store_v2::PresentationMarkerRows, _>(|row| {
            row.verify_key(&store_v2::SingletonKey)?;
            row.verify_indexes(&store_v2::IndexKeys::none())?;
            let marker: PresentationMarker = decode_exact(&row.payload)?;
            if marker.transaction_id == [0u8; 16] {
                return Err(StoreError::LogicalKeyMismatch);
            }
            Ok(())
        })
    }

    /// Arm one deterministic transaction failure for the next matching point.
    #[cfg(feature = "test-failpoints")]
    #[doc(hidden)]
    pub fn arm_commit_failpoint(&self, point: CommitFailpoint, failure: CommitFailure) {
        self.commit_failpoint
            .replace(Some(ArmedCommitFailpoint { point, failure }));
    }

    /// Remove any armed deterministic transaction failure.
    #[cfg(feature = "test-failpoints")]
    #[doc(hidden)]
    pub fn clear_commit_failpoint(&self) {
        self.commit_failpoint.replace(None);
    }

    fn validate_commit_plan(&self, plan: &CommitPlan<'_>) -> Result<()> {
        match plan {
            CommitPlan::PairwiseSend(plan) => self.validate_pairwise_send(plan),
            CommitPlan::PairwiseReceive(plan) => self.validate_pairwise_receive(plan),
            CommitPlan::HandshakeReceive(plan) => self.validate_handshake_receive(plan),
            CommitPlan::ReceiptReceive(plan) => self.validate_receipt_receive(plan),
            CommitPlan::Maintenance(plan) => self.validate_maintenance(plan),
        }
    }

    fn validate_pairwise_send(&self, plan: &PairwiseSendPlan<'_>) -> Result<()> {
        if plan.sessions.is_empty()
            || plan.sessions.len() > MAX_PAIRWISE_COMMIT_DEVICES
            || plan.queue.is_empty()
            || plan.queue.len() > MAX_COMMIT_QUEUE_ROWS
            || mutation_count([
                plan.sessions.len(),
                usize::from(plan.message.is_some()),
                usize::from(plan.message_update.is_some()),
                plan.deliveries.len(),
                plan.delivery_updates.len(),
                plan.queue.len(),
                usize::from(plan.scheduled.is_some()),
                plan.clear_capabilities.len(),
                plan.clear_reset_markers.len(),
                usize::from(plan.ephemeral.is_some()),
            ])? > MAX_COMMIT_MUTATIONS
        {
            return Err(StoreError::InvalidTransition);
        }
        let routes = plan
            .sessions
            .iter()
            .map(|transition| transition.peer_device)
            .collect::<HashSet<_>>();
        let queue_ids = plan
            .queue
            .iter()
            .map(|item| item.envelope.content_id())
            .collect::<HashSet<_>>();
        if routes.len() != plan.sessions.len()
            || queue_ids.len() != plan.queue.len()
            || plan.queue.iter().any(|item| !routes.contains(&item.peer))
            || plan.queue.iter().any(|item| item.group_msg_id.is_some())
            || routes
                .iter()
                .any(|route| !plan.queue.iter().any(|item| item.peer == *route))
        {
            return Err(StoreError::InvalidTransition);
        }
        for transition in plan.sessions {
            self.validate_session_transition(transition)?;
        }
        if plan.message.is_some() && plan.message_update.is_some() {
            return Err(StoreError::InvalidTransition);
        }
        let history_id = if let Some(message) = plan.message {
            if message.direction != Direction::Outbound
                || message.state != DeliveryState::Queued
                || self
                    .messages_with(&message.peer)?
                    .iter()
                    .any(|existing| existing.id == message.id)
                || plan
                    .queue
                    .iter()
                    .any(|item| item.msg_id != Some(message.id))
                || plan.deliveries.iter().any(|delivery| {
                    delivery.message != message.id || delivery.account != message.peer
                })
            {
                return Err(StoreError::InvalidTransition);
            }
            Some(message.id)
        } else if let Some(transition) = &plan.message_update {
            self.validate_message_transition(transition)?;
            if transition.after.direction != Direction::Outbound
                || plan
                    .queue
                    .iter()
                    .any(|item| item.msg_id != Some(transition.after.id))
            {
                return Err(StoreError::InvalidTransition);
            }
            Some(transition.after.id)
        } else {
            None
        };
        if history_id.is_none()
            && (!plan.deliveries.is_empty()
                || !plan.delivery_updates.is_empty()
                || plan.queue.iter().any(|item| item.msg_id.is_some()))
        {
            return Err(StoreError::InvalidTransition);
        }
        if plan.deliveries.iter().any(|delivery| {
            Some(delivery.message) != history_id || delivery.state != DeliveryState::Queued
        }) {
            return Err(StoreError::InvalidTransition);
        }
        if plan
            .delivery_updates
            .iter()
            .any(|transition| Some(transition.after.message) != history_id)
        {
            return Err(StoreError::InvalidTransition);
        }
        let mut delivery_routes = HashSet::new();
        if plan
            .deliveries
            .iter()
            .map(|delivery| delivery.device)
            .chain(
                plan.delivery_updates
                    .iter()
                    .map(|transition| transition.after.device),
            )
            .any(|device| !delivery_routes.insert(device))
        {
            return Err(StoreError::InvalidTransition);
        }
        for transition in plan.delivery_updates {
            self.validate_delivery_transition(transition)?;
        }
        if let Some(history_id) = history_id {
            let history_peer = plan.message.map_or_else(
                || {
                    plan.message_update
                        .as_ref()
                        .expect("history exists")
                        .after
                        .peer
                },
                |message| message.peer,
            );
            let existing_queue = self.queue_all()?;
            for delivery in plan.deliveries.iter().chain(
                plan.delivery_updates
                    .iter()
                    .map(|transition| transition.after),
            ) {
                if delivery.account != history_peer || delivery.state != DeliveryState::Queued {
                    return Err(StoreError::InvalidTransition);
                }
                if let Some(wire_id) = delivery.wire_id {
                    let owned = plan.queue.iter().any(|item| {
                        item.peer == delivery.device
                            && item.msg_id == Some(history_id)
                            && item.envelope.content_id() == wire_id
                    }) || existing_queue.iter().any(|(_, item)| {
                        item.peer == delivery.device
                            && item.msg_id == Some(history_id)
                            && item.envelope.content_id() == wire_id
                    });
                    if !owned {
                        return Err(StoreError::InvalidTransition);
                    }
                }
            }
            for item in plan.queue {
                let wire_id = item.envelope.content_id();
                let owners = plan
                    .deliveries
                    .iter()
                    .filter(|delivery| {
                        delivery.message == history_id
                            && delivery.account == history_peer
                            && delivery.device == item.peer
                            && delivery.wire_id == Some(wire_id)
                            && delivery.state == DeliveryState::Queued
                    })
                    .count()
                    + plan
                        .delivery_updates
                        .iter()
                        .filter(|transition| {
                            transition.after.message == history_id
                                && transition.after.account == history_peer
                                && transition.after.device == item.peer
                                && transition.after.wire_id == Some(wire_id)
                                && transition.after.state == DeliveryState::Queued
                        })
                        .count();
                if owners != 1 {
                    return Err(StoreError::InvalidTransition);
                }
            }
        }
        if let Some(scheduled) = plan.scheduled {
            if self.get_scheduled_message(&scheduled.id)?.as_ref() != Some(scheduled)
                || plan
                    .message
                    .is_none_or(|message| message.id != scheduled.id)
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        let reset_markers = self.reset_markers()?.into_iter().collect::<HashSet<_>>();
        if plan
            .clear_reset_markers
            .iter()
            .any(|marker| !reset_markers.contains(marker))
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_pairwise_receive(&self, plan: &PairwiseReceivePlan<'_>) -> Result<()> {
        self.validate_session_transition(&plan.session)?;
        if plan.content_id == [0u8; 16]
            || plan.message.is_some_and(|message| {
                message.direction != Direction::Inbound
                    || message.state != DeliveryState::Received
                    || message.wire_id.is_some()
            })
            || plan.queue.iter().any(|item| {
                item.peer != plan.session.peer_device
                    || item.msg_id.is_some()
                    || item.group_msg_id.is_some()
                    || item.envelope.kind != EnvelopeKind::Receipt
            })
            || plan.queue.len() > MAX_COMMIT_QUEUE_ROWS
            || mutation_count([
                1,
                usize::from(plan.message.is_some()),
                usize::from(plan.ephemeral.is_some()),
                plan.media_transfers.len(),
                plan.media_objects.len(),
                usize::from(plan.capabilities.is_some()),
                plan.queue.len(),
                1,
                usize::from(plan.receipt_replay),
                usize::from(plan.source_pending.is_some()),
            ])? > MAX_COMMIT_MUTATIONS
        {
            return Err(StoreError::InvalidTransition);
        }
        if let Some(message) = plan.message {
            self.validate_new_message(message)?;
        }
        self.validate_pending(plan.source_pending)?;
        self.validate_new_media(plan.media_transfers, plan.media_objects)?;
        let accepted_state = plan.message.is_some()
            || plan.ephemeral.is_some()
            || !plan.media_transfers.is_empty()
            || !plan.media_objects.is_empty()
            || plan.capabilities.is_some();
        if (plan.receipt_replay && plan.queue.is_empty())
            || (accepted_state && (!plan.receipt_replay || plan.queue.is_empty()))
            || (self.is_seen(&plan.content_id)?
                && (accepted_state || !plan.receipt_replay || plan.queue.is_empty()))
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_handshake_receive(&self, plan: &HandshakeReceivePlan<'_>) -> Result<()> {
        self.validate_session_transition(&plan.session)?;
        if plan.content_id == [0u8; 16]
            || plan.devices.is_empty()
            || plan.devices.len() > MAX_PAIRWISE_COMMIT_DEVICES
            || plan.queue.len() > MAX_COMMIT_QUEUE_ROWS
            || plan.delete_queue.len() > MAX_COMMIT_QUEUE_ROWS
            || plan
                .devices
                .iter()
                .any(|device| device.account != plan.contact.peer)
            || plan.queue.iter().any(|item| {
                item.peer != plan.session.peer_device
                    || item.msg_id.is_some()
                    || item.group_msg_id.is_some()
                    || item.envelope.kind != EnvelopeKind::Receipt
            })
            || mutation_count([
                usize::from(plan.prekeys.is_some()),
                1,
                1,
                plan.devices.len(),
                plan.delete_devices.len(),
                plan.delete_sessions.len(),
                plan.delete_capabilities.len(),
                plan.delete_queue.len(),
                plan.groups.len(),
                usize::from(plan.message.is_some()),
                usize::from(plan.ephemeral.is_some()),
                plan.media_transfers.len(),
                plan.media_objects.len(),
                plan.queue.len(),
                1,
                usize::from(plan.receipt_replay),
                usize::from(plan.source_pending.is_some()),
            ])? > MAX_COMMIT_MUTATIONS
        {
            return Err(StoreError::InvalidTransition);
        }
        let device_ids = plan
            .devices
            .iter()
            .map(|device| device.device)
            .collect::<HashSet<_>>();
        if device_ids.len() != plan.devices.len()
            || plan
                .delete_devices
                .iter()
                .any(|delete| device_ids.contains(&delete.before.device))
        {
            return Err(StoreError::InvalidTransition);
        }
        for delete in plan.delete_devices {
            if self
                .contact_devices_for(&delete.before.account)?
                .into_iter()
                .find(|endpoint| endpoint.device == delete.before.device)
                .as_ref()
                != Some(delete.before)
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        for peer in plan.delete_sessions {
            if peer == &plan.session.peer_device || self.get_session(peer)?.is_none() {
                return Err(StoreError::InvalidTransition);
            }
        }
        for delete in plan.delete_queue {
            self.validate_queue_delete(*delete)?;
        }
        if let Some(prekeys) = &plan.prekeys {
            let current = self.get_prekeys()?;
            if prekeys.before == prekeys.after
                || current.as_ref().map(|value| value.as_slice()) != Some(prekeys.before)
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        for group in plan.groups {
            self.validate_group_transition(group)?;
        }
        if let Some(message) = plan.message {
            if message.peer != plan.contact.peer {
                return Err(StoreError::InvalidTransition);
            }
            self.validate_new_message(message)?;
        }
        self.validate_pending(plan.source_pending)?;
        self.validate_new_media(plan.media_transfers, plan.media_objects)?;
        let accepted_state = plan.message.is_some()
            || plan.ephemeral.is_some()
            || !plan.media_transfers.is_empty()
            || !plan.media_objects.is_empty();
        if self.is_seen(&plan.content_id)?
            || (plan.receipt_replay && plan.queue.is_empty())
            || (accepted_state && (!plan.receipt_replay || plan.queue.is_empty()))
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_receipt_receive(&self, plan: &ReceiptReceivePlan<'_>) -> Result<()> {
        self.validate_session_transition(&plan.session)?;
        if plan.queue.len() > MAX_COMMIT_QUEUE_ROWS
            || plan.content_id == [0u8; 16]
            || self.is_seen(&plan.content_id)?
            || plan.queue.iter().any(|item| {
                item.peer != plan.session.peer_device
                    || item.msg_id.is_some()
                    || item.group_msg_id.is_some()
            })
            || mutation_count([
                1,
                plan.delete_queue.len(),
                plan.queue.len(),
                plan.messages.len(),
                plan.deliveries.len(),
                plan.group_messages.len(),
                plan.groups.len(),
                plan.media_transfers.len(),
                plan.media_objects.len(),
                usize::from(plan.capabilities.is_some()),
                usize::from(plan.deferred_control.is_some()),
                1,
                usize::from(plan.source_pending.is_some()),
            ])? > MAX_COMMIT_MUTATIONS
        {
            return Err(StoreError::InvalidTransition);
        }
        for delete in plan.delete_queue {
            self.validate_queue_delete(*delete)?;
            if self
                .store_queue_row(delete.sequence)?
                .is_none_or(|item| item.peer != plan.session.peer_device)
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        for transition in plan.messages {
            self.validate_message_transition(transition)?;
        }
        for transition in plan.deliveries {
            self.validate_delivery_transition(transition)?;
        }
        for transition in plan.group_messages {
            self.validate_group_message_transition(transition)?;
        }
        for transition in plan.groups {
            self.validate_group_transition(transition)?;
        }
        self.validate_new_media(plan.media_transfers, plan.media_objects)?;
        if let Some(control) = plan.deferred_control {
            if control.content_id != plan.content_id
                || control.peer_device != plan.session.peer_device
                || control.body.is_empty()
                || self.get_deferred_control(&control.content_id)?.is_some()
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        self.validate_pending(plan.source_pending)
    }

    fn validate_maintenance(&self, plan: &MaintenancePlan<'_>) -> Result<()> {
        let count = mutation_count([
            plan.seen.len(),
            plan.delete_pending.len(),
            plan.delete_queue.len(),
            plan.update_queue.len(),
            plan.delete_replay.len(),
            plan.messages.len(),
            plan.deliveries.len(),
            plan.group_messages.len(),
            plan.groups.len(),
            plan.ephemeral.len(),
            plan.delete_messages.len(),
            plan.delete_group_messages.len(),
            plan.delete_media
                .iter()
                .map(|delete| delete.object_ids.len() + 1)
                .sum(),
            plan.delete_scheduled.len(),
            plan.delete_sessions.len(),
            plan.delete_capabilities.len(),
            plan.clear_reset_markers.len(),
            plan.delete_controls.len(),
            usize::from(plan.acknowledge_presentation.is_some()),
        ])?;
        if count == 0 || count > MAX_MAINTENANCE_TRANSITIONS {
            return Err(StoreError::MaintenanceBounds);
        }
        for delete in plan.delete_pending {
            self.validate_pending(Some(*delete))?;
        }
        for delete in plan.delete_queue {
            self.validate_queue_delete(*delete)?;
        }
        for transition in plan.update_queue {
            let current = self
                .store_queue_row(transition.sequence)?
                .ok_or(StoreError::InvalidTransition)?;
            if current != *transition.before
                || transition.before.envelope.content_id() != transition.after.envelope.content_id()
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        for transition in plan.messages {
            self.validate_message_transition(transition)?;
        }
        for transition in plan.deliveries {
            self.validate_delivery_transition(transition)?;
        }
        for transition in plan.group_messages {
            self.validate_group_message_transition(transition)?;
        }
        for transition in plan.groups {
            self.validate_group_transition(transition)?;
        }
        for transition in plan.ephemeral {
            let current = self.get_ephemeral_record(
                &transition.after.conversation,
                &transition.after.author,
                &transition.after.content_id,
            )?;
            if current.as_ref() != transition.before
                || transition
                    .before
                    .is_some_and(|before| before.state != EphemeralState::Active)
                || transition.after.state == EphemeralState::Active
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        for delete in plan.delete_messages {
            let current = self
                .messages_with(&delete.before.peer)?
                .into_iter()
                .find(|message| message.id == delete.before.id);
            if current.as_ref() != Some(delete.before) {
                return Err(StoreError::InvalidTransition);
            }
        }
        for delete in plan.delete_group_messages {
            if self
                .group_messages(&delete.before.group)?
                .into_iter()
                .find(|message| {
                    message.id == delete.before.id && message.sender == delete.before.sender
                })
                .as_ref()
                != Some(delete.before)
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        for delete in plan.delete_media {
            let transfer = self
                .get_media_transfer(&delete.transfer_id)?
                .ok_or(StoreError::InvalidTransition)?;
            if !matches!(transfer, crate::MediaRecord::Available(_)) {
                return Err(StoreError::InvalidTransition);
            }
            let current_objects = self
                .media_objects_for_transfer(&delete.transfer_id)?
                .into_iter()
                .map(|object| object.local_id)
                .collect::<HashSet<_>>();
            if current_objects.len() != delete.object_ids.len()
                || delete
                    .object_ids
                    .iter()
                    .any(|object| !current_objects.contains(object))
            {
                return Err(StoreError::InvalidTransition);
            }
        }
        for scheduled in plan.delete_scheduled {
            if self.get_scheduled_message(&scheduled.id)?.as_ref() != Some(scheduled) {
                return Err(StoreError::InvalidTransition);
            }
        }
        let delete_sessions = plan.delete_sessions.iter().copied().collect::<HashSet<_>>();
        if delete_sessions.len() != plan.delete_sessions.len() {
            return Err(StoreError::InvalidTransition);
        }
        for peer in plan.delete_sessions {
            if self.get_session(peer)?.is_none() {
                return Err(StoreError::InvalidTransition);
            }
        }
        let delete_capabilities = plan
            .delete_capabilities
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        if delete_capabilities.len() != plan.delete_capabilities.len() {
            return Err(StoreError::InvalidTransition);
        }
        for peer in plan.delete_capabilities {
            if self.get_capabilities(peer)?.is_none() {
                return Err(StoreError::InvalidTransition);
            }
        }
        let reset_markers = self.reset_markers()?.into_iter().collect::<HashSet<_>>();
        if plan
            .clear_reset_markers
            .iter()
            .any(|marker| !reset_markers.contains(marker))
        {
            return Err(StoreError::InvalidTransition);
        }
        for control in plan.delete_controls {
            if self.get_deferred_control(&control.content_id)?.as_ref() != Some(control) {
                return Err(StoreError::InvalidTransition);
            }
        }
        if let Some(marker) = plan.acknowledge_presentation {
            if self.presentation_resync_marker()? != Some(marker) {
                return Err(StoreError::InvalidTransition);
            }
        }
        Ok(())
    }

    fn validate_session_transition(&self, transition: &SessionTransition<'_>) -> Result<()> {
        let current = self.get_session(&transition.peer_device)?;
        if !session_eq(current.as_ref(), transition.before)?
            || session_eq(Some(transition.after), transition.before)?
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_pending(&self, pending: Option<PendingDelete>) -> Result<()> {
        let Some(pending) = pending else {
            return Ok(());
        };
        let row = self
            .row_by_rowid::<store_v2::PendingRows>(pending.sequence)?
            .ok_or(StoreError::InvalidTransition)?;
        let (encoded, _): (Vec<u8>, u64) = decode_exact(&row.payload)?;
        if Envelope::decode(&encoded)?.content_id() != pending.content_id {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_queue_delete(&self, delete: QueueDelete) -> Result<()> {
        let item = self
            .store_queue_row(delete.sequence)?
            .ok_or(StoreError::InvalidTransition)?;
        if item.envelope.content_id() != delete.content_id {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn store_queue_row(&self, sequence: i64) -> Result<Option<QueueItem>> {
        self.row_by_rowid::<store_v2::QueueRows>(sequence)?
            .map(|row| Self::decode_queue_item(&row.payload))
            .transpose()
    }

    fn validate_message_transition(&self, transition: &MessageTransition<'_>) -> Result<()> {
        if transition.before.id != transition.after.id
            || transition.before.peer != transition.after.peer
            || transition.before.direction != transition.after.direction
            || self
                .messages_with(&transition.before.peer)?
                .into_iter()
                .find(|message| message.id == transition.before.id)
                .as_ref()
                != Some(transition.before)
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_new_message(&self, message: &MessageRecord) -> Result<()> {
        if self
            .messages_with(&message.peer)?
            .into_iter()
            .any(|existing| existing.id == message.id && existing.direction == message.direction)
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_delivery_transition(&self, transition: &DeliveryTransition<'_>) -> Result<()> {
        if transition.before.message != transition.after.message
            || transition.before.account != transition.after.account
            || transition.before.device != transition.after.device
            || self
                .message_device_deliveries(&transition.before.message)?
                .into_iter()
                .find(|delivery| delivery.device == transition.before.device)
                .as_ref()
                != Some(transition.before)
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_group_transition(&self, transition: &GroupTransition<'_>) -> Result<()> {
        if transition.before.id != transition.after.id
            || self.get_group(&transition.before.id)?.as_ref() != Some(transition.before)
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_group_message_transition(
        &self,
        transition: &GroupMessageTransition<'_>,
    ) -> Result<()> {
        if transition.before.id != transition.after.id
            || transition.before.group != transition.after.group
            || transition.before.sender != transition.after.sender
            || transition.before.direction != transition.after.direction
            || self
                .group_messages(&transition.before.group)?
                .into_iter()
                .find(|message| {
                    message.id == transition.before.id && message.sender == transition.before.sender
                })
                .as_ref()
                != Some(transition.before)
        {
            return Err(StoreError::InvalidTransition);
        }
        Ok(())
    }

    fn validate_new_media(
        &self,
        transfers: &[MediaTransferRecord],
        objects: &[MediaObjectRecord],
    ) -> Result<()> {
        let transfer_ids = transfers
            .iter()
            .map(|transfer| transfer.local_id)
            .collect::<HashSet<_>>();
        let object_ids = objects
            .iter()
            .map(|object| object.local_id)
            .collect::<HashSet<_>>();
        if transfer_ids.len() != transfers.len()
            || object_ids.len() != objects.len()
            || objects
                .iter()
                .any(|object| !transfer_ids.contains(&object.transfer_id))
        {
            return Err(StoreError::InvalidTransition);
        }
        for transfer in transfers {
            if self.get_media_transfer(&transfer.local_id)?.is_some() {
                return Err(StoreError::InvalidTransition);
            }
        }
        for object in objects {
            if self.get_media_object(&object.local_id)?.is_some() {
                return Err(StoreError::InvalidTransition);
            }
        }
        Ok(())
    }

    /// Read one accepted deferred control by its envelope id.
    pub fn get_deferred_control(
        &self,
        content_id: &[u8; 16],
    ) -> Result<Option<DeferredControlRecord>> {
        let key = store_v2::ContentKey::new(*content_id);
        self.get_equality::<store_v2::DeferredControlRows>(&key)?
            .map(|row| {
                row.verify_key(&key)?;
                let control: DeferredControlRecord = decode_exact(&row.payload)?;
                if control.content_id != *content_id {
                    return Err(StoreError::LogicalKeyMismatch);
                }
                Ok(control)
            })
            .transpose()
    }

    /// Return a bounded page of accepted controls in stable row order.
    pub fn deferred_controls(&self, limit: usize) -> Result<Vec<DeferredControlRecord>> {
        if limit == 0 || limit > MAX_DEFERRED_CONTROLS {
            return Err(StoreError::RecordBounds);
        }
        self.rows::<store_v2::DeferredControlRows>()?
            .into_iter()
            .take(limit)
            .map(|row| {
                let control: DeferredControlRecord = decode_exact(&row.payload)?;
                row.verify_key(&store_v2::ContentKey::new(control.content_id))?;
                Ok(control)
            })
            .collect()
    }

    pub(crate) fn validate_deferred_controls(&self) -> Result<()> {
        self.validate_rows::<store_v2::DeferredControlRows, _>(|row| {
            let control: DeferredControlRecord = decode_exact(&row.payload)?;
            if control.content_id == [0u8; 16]
                || control.body.is_empty()
                || control.body.len() > store_v2::MAX_RECORD_BYTES
            {
                return Err(StoreError::RecordBounds);
            }
            row.verify_key(&store_v2::ContentKey::new(control.content_id))?;
            row.verify_indexes(&store_v2::IndexKeys::none())
        })
    }

    fn check_commit_failpoint(&self, point: CommitPoint) -> Result<()> {
        #[cfg(feature = "test-failpoints")]
        {
            let armed = *self.commit_failpoint.borrow();
            if armed.is_some_and(|armed| armed.point == point.into_public()) {
                self.commit_failpoint.replace(None);
                return Err(match armed.expect("checked above").failure {
                    CommitFailure::Interrupted => {
                        StoreError::Io(std::io::Error::from(std::io::ErrorKind::Interrupted))
                    }
                    CommitFailure::DiskFull => {
                        StoreError::Io(std::io::Error::from(std::io::ErrorKind::StorageFull))
                    }
                    CommitFailure::Constraint => StoreError::InvalidTransition,
                    CommitFailure::Duplicate => StoreError::DuplicateIndex,
                });
            }
        }
        #[cfg(not(feature = "test-failpoints"))]
        match point {
            CommitPoint::BeforeStatement(index) | CommitPoint::AfterStatement(index) => {
                let _ = index;
            }
            _ => {}
        }
        Ok(())
    }
}

struct CommitWriter<'a, R> {
    store: &'a Store,
    rng: &'a mut R,
    statement: usize,
    records: CommittedRecordIds,
}

impl<R: CryptoRngCore> CommitWriter<'_, R> {
    fn write<T>(&mut self, operation: impl FnOnce(&Store, &mut R) -> Result<T>) -> Result<T> {
        self.store
            .check_commit_failpoint(CommitPoint::BeforeStatement(self.statement))?;
        let value = operation(self.store, self.rng)?;
        self.store
            .check_commit_failpoint(CommitPoint::AfterStatement(self.statement))?;
        self.statement += 1;
        Ok(value)
    }

    fn session(&mut self, transition: &SessionTransition<'_>) -> Result<()> {
        self.write(|store, rng| {
            let payload = Zeroizing::new(
                postcard::to_allocvec(transition.after).map_err(|_| StoreError::Serialization)?,
            );
            store.put_equality::<store_v2::SessionRows>(
                &store_v2::AccountKey::new(transition.peer_device),
                &payload,
                store_v2::IndexKeys::none(),
                rng,
            )
        })
    }

    fn queue(&mut self, items: &[QueueItem]) -> Result<()> {
        for item in items {
            let sequence = self.write(|store, rng| store.queue_push(item, rng))?;
            self.records.queue_sequences.push(sequence);
        }
        Ok(())
    }

    fn pending(&mut self, pending: Option<PendingDelete>) -> Result<()> {
        if let Some(pending) = pending {
            self.write(|store, _| {
                if store.delete_rowid::<store_v2::PendingRows>(pending.sequence)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        Ok(())
    }

    fn pairwise_send(&mut self, plan: &PairwiseSendPlan<'_>) -> Result<()> {
        for transition in plan.sessions {
            self.session(transition)?;
        }
        if let Some(message) = plan.message {
            self.write(|store, rng| store.put_message(message, rng))?;
            self.records.messages.push(message.id);
        }
        if let Some(transition) = &plan.message_update {
            self.write(|store, rng| {
                if store.update_message(transition.after, rng)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
            self.records.messages.push(transition.after.id);
        }
        for delivery in plan.deliveries {
            self.write(|store, rng| store.put_message_device_delivery(delivery, rng))?;
        }
        for transition in plan.delivery_updates {
            self.write(|store, rng| store.put_message_device_delivery(transition.after, rng))?;
        }
        self.queue(plan.queue)?;
        if let Some(scheduled) = plan.scheduled {
            self.write(|store, _| {
                if store.delete_scheduled_message(&scheduled.id)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for peer in plan.clear_capabilities {
            self.write(|store, _| store.delete_capabilities(peer))?;
        }
        for marker in plan.clear_reset_markers {
            self.write(|store, _| store.clear_reset_marker(marker))?;
        }
        if let Some(ephemeral) = plan.ephemeral {
            self.write(|store, rng| store.put_ephemeral_record(ephemeral, rng))?;
        }
        Ok(())
    }

    fn pairwise_receive(&mut self, plan: &PairwiseReceivePlan<'_>) -> Result<()> {
        self.session(&plan.session)?;
        if let Some(message) = plan.message {
            self.write(|store, rng| store.put_message(message, rng))?;
            self.records.messages.push(message.id);
        }
        if let Some(ephemeral) = plan.ephemeral {
            self.write(|store, rng| store.put_ephemeral_record(ephemeral, rng))?;
        }
        for transfer in plan.media_transfers {
            self.write(|store, rng| store.put_media_transfer(transfer, rng))?;
        }
        for object in plan.media_objects {
            self.write(|store, rng| store.put_media_object(object, rng))?;
        }
        if let Some(capabilities) = plan.capabilities {
            let peer = plan.session.peer_device;
            self.write(|store, rng| store.put_capabilities(&peer, capabilities, rng))?;
        }
        self.queue(plan.queue)?;
        self.write(|store, rng| {
            store.put_equality::<store_v2::SeenRows>(
                &store_v2::ContentKey::new(plan.content_id),
                &plan.content_id,
                store_v2::IndexKeys::none(),
                rng,
            )
        })?;
        if plan.receipt_replay {
            let peer = plan.session.peer_device;
            self.write(|store, rng| {
                store.put_receipt_replay(&plan.content_id, &peer, plan.received_at, rng)
            })?;
        }
        self.pending(plan.source_pending)
    }

    fn handshake_receive(&mut self, plan: &HandshakeReceivePlan<'_>) -> Result<()> {
        if let Some(prekeys) = &plan.prekeys {
            self.write(|store, rng| store.put_prekeys(prekeys.after, rng))?;
        }
        self.session(&plan.session)?;
        self.write(|store, rng| store.put_contact(plan.contact, rng))?;
        for device in plan.devices {
            self.write(|store, rng| store.put_contact_device(device, rng))?;
        }
        for delete in plan.delete_devices {
            self.write(|store, _| {
                store.delete_contact_device(&delete.before.account, &delete.before.device)
            })?;
        }
        for peer in plan.delete_sessions {
            self.write(|store, _| store.delete_session(peer))?;
        }
        for peer in plan.delete_capabilities {
            self.write(|store, _| store.delete_capabilities(peer))?;
        }
        for delete in plan.delete_queue {
            self.write(|store, _| {
                if store.delete_rowid::<store_v2::QueueRows>(delete.sequence)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for group in plan.groups {
            self.write(|store, rng| store.put_group(group.after, rng))?;
        }
        if let Some(message) = plan.message {
            self.write(|store, rng| store.put_message(message, rng))?;
            self.records.messages.push(message.id);
        }
        if let Some(ephemeral) = plan.ephemeral {
            self.write(|store, rng| store.put_ephemeral_record(ephemeral, rng))?;
        }
        for transfer in plan.media_transfers {
            self.write(|store, rng| store.put_media_transfer(transfer, rng))?;
        }
        for object in plan.media_objects {
            self.write(|store, rng| store.put_media_object(object, rng))?;
        }
        self.queue(plan.queue)?;
        self.write(|store, rng| {
            store.put_equality::<store_v2::SeenRows>(
                &store_v2::ContentKey::new(plan.content_id),
                &plan.content_id,
                store_v2::IndexKeys::none(),
                rng,
            )
        })?;
        if plan.receipt_replay {
            let peer = plan.session.peer_device;
            self.write(|store, rng| {
                store.put_receipt_replay(&plan.content_id, &peer, plan.received_at, rng)
            })?;
        }
        self.pending(plan.source_pending)
    }

    fn receipt_receive(&mut self, plan: &ReceiptReceivePlan<'_>) -> Result<()> {
        self.session(&plan.session)?;
        for delete in plan.delete_queue {
            self.write(|store, _| {
                if store.delete_rowid::<store_v2::QueueRows>(delete.sequence)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        self.queue(plan.queue)?;
        for transition in plan.messages {
            self.write(|store, rng| {
                if store.update_message(transition.after, rng)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
            self.records.messages.push(transition.after.id);
        }
        for transition in plan.deliveries {
            self.write(|store, rng| store.put_message_device_delivery(transition.after, rng))?;
        }
        for transition in plan.group_messages {
            self.write(|store, rng| {
                if store.update_group_message(transition.after, rng)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for transition in plan.groups {
            self.write(|store, rng| store.put_group(transition.after, rng))?;
        }
        for transfer in plan.media_transfers {
            self.write(|store, rng| store.put_media_transfer(transfer, rng))?;
        }
        for object in plan.media_objects {
            self.write(|store, rng| store.put_media_object(object, rng))?;
        }
        if let Some(capabilities) = plan.capabilities {
            let peer = plan.session.peer_device;
            self.write(|store, rng| store.put_capabilities(&peer, capabilities, rng))?;
        }
        if let Some(control) = plan.deferred_control {
            self.write(|store, rng| {
                let encoded =
                    postcard::to_allocvec(control).map_err(|_| StoreError::Serialization)?;
                store.put_equality::<store_v2::DeferredControlRows>(
                    &store_v2::ContentKey::new(control.content_id),
                    &encoded,
                    store_v2::IndexKeys::none(),
                    rng,
                )
            })?;
        }
        self.write(|store, rng| {
            store.put_equality::<store_v2::SeenRows>(
                &store_v2::ContentKey::new(plan.content_id),
                &plan.content_id,
                store_v2::IndexKeys::none(),
                rng,
            )
        })?;
        self.pending(plan.source_pending)
    }

    fn maintenance(&mut self, plan: &MaintenancePlan<'_>) -> Result<()> {
        for content_id in plan.seen {
            self.write(|store, rng| {
                store.put_equality::<store_v2::SeenRows>(
                    &store_v2::ContentKey::new(*content_id),
                    content_id,
                    store_v2::IndexKeys::none(),
                    rng,
                )
            })?;
        }
        for pending in plan.delete_pending {
            self.pending(Some(*pending))?;
        }
        for delete in plan.delete_queue {
            self.write(|store, _| {
                if store.delete_rowid::<store_v2::QueueRows>(delete.sequence)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for transition in plan.update_queue {
            self.write(|store, rng| {
                store.queue_update(transition.sequence, transition.after, rng)
            })?;
        }
        for content_id in plan.delete_replay {
            self.write(|store, _| {
                store.delete_equality::<store_v2::ReceiptReplayRows>(
                    &store_v2::ContentKey::new(*content_id),
                )?;
                Ok(())
            })?;
        }
        for transition in plan.messages {
            self.write(|store, rng| {
                if store.update_message(transition.after, rng)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
            self.records.messages.push(transition.after.id);
        }
        for transition in plan.deliveries {
            self.write(|store, rng| store.put_message_device_delivery(transition.after, rng))?;
        }
        for transition in plan.group_messages {
            self.write(|store, rng| {
                if store.update_group_message(transition.after, rng)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for transition in plan.groups {
            self.write(|store, rng| store.put_group(transition.after, rng))?;
        }
        for transition in plan.ephemeral {
            self.write(|store, rng| store.put_ephemeral_record(transition.after, rng))?;
        }
        for delete in plan.delete_messages {
            self.write(|store, _| {
                if store.delete_message_record(
                    &delete.before.peer,
                    delete.before.direction,
                    &delete.before.id,
                )? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for delete in plan.delete_group_messages {
            self.write(|store, _| {
                if store.delete_group_message_record(
                    &delete.before.group,
                    &delete.before.sender,
                    &delete.before.id,
                )? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for delete in plan.delete_media {
            for object_id in delete.object_ids {
                self.write(|store, _| {
                    if store.delete_equality::<store_v2::MediaObjectRows>(
                        &store_v2::LocalIdKey::new(*object_id),
                    )? {
                        Ok(())
                    } else {
                        Err(StoreError::InvalidTransition)
                    }
                })?;
            }
            self.write(|store, _| {
                if store.delete_equality::<store_v2::MediaTransferRows>(
                    &store_v2::LocalIdKey::new(delete.transfer_id),
                )? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for scheduled in plan.delete_scheduled {
            self.write(|store, _| {
                if store.delete_scheduled_message(&scheduled.id)? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for peer in plan.delete_sessions {
            self.write(|store, _| {
                if store
                    .delete_equality::<store_v2::SessionRows>(&store_v2::AccountKey::new(*peer))?
                {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for peer in plan.delete_capabilities {
            self.write(|store, _| {
                if store.delete_equality::<store_v2::CapabilityRows>(&store_v2::AccountKey::new(
                    *peer,
                ))? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        for marker in plan.clear_reset_markers {
            self.write(|store, _| store.clear_reset_marker(marker))?;
        }
        for control in plan.delete_controls {
            self.write(|store, _| {
                if store.delete_equality::<store_v2::DeferredControlRows>(
                    &store_v2::ContentKey::new(control.content_id),
                )? {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        if let Some(marker) = plan.acknowledge_presentation {
            self.write(|store, _| {
                if store.presentation_resync_marker()? != Some(marker) {
                    return Err(StoreError::InvalidTransition);
                }
                if store
                    .delete_equality::<store_v2::PresentationMarkerRows>(&store_v2::SingletonKey)?
                {
                    Ok(())
                } else {
                    Err(StoreError::InvalidTransition)
                }
            })?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum CommitPoint {
    BeforeBegin,
    AfterBegin,
    BeforeStatement(usize),
    AfterStatement(usize),
    BeforeCommit,
    AfterCommit,
}

#[cfg(feature = "test-failpoints")]
impl CommitPoint {
    fn into_public(self) -> CommitFailpoint {
        match self {
            Self::BeforeBegin => CommitFailpoint::BeforeBegin,
            Self::AfterBegin => CommitFailpoint::AfterBegin,
            Self::BeforeStatement(index) => CommitFailpoint::BeforeStatement(index),
            Self::AfterStatement(index) => CommitFailpoint::AfterStatement(index),
            Self::BeforeCommit => CommitFailpoint::BeforeCommit,
            Self::AfterCommit => CommitFailpoint::AfterCommit,
        }
    }
}

fn session_eq(left: Option<&Session>, right: Option<&Session>) -> Result<bool> {
    match (left, right) {
        (None, None) => Ok(true),
        (Some(left), Some(right)) => {
            let left = postcard::to_allocvec(left).map_err(|_| StoreError::Serialization)?;
            let right = postcard::to_allocvec(right).map_err(|_| StoreError::Serialization)?;
            Ok(left == right)
        }
        _ => Ok(false),
    }
}

fn mutation_count<const N: usize>(counts: [usize; N]) -> Result<usize> {
    counts.into_iter().try_fold(0usize, |sum, count| {
        sum.checked_add(count).ok_or(StoreError::RecordBounds)
    })
}
