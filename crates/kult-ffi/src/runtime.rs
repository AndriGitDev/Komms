//! The embedded runtime behind the FFI surface: one [`Node`] owned by an
//! actor task, a delivery-engine tick loop, and the same connectivity
//! lifecycle `kultd` runs (DHT bootstrap + bundle publication, NAT probing
//! with relay reservation, mailbox check-ins) — composed in-process, with
//! events handed to the application's listener instead of a socket
//! (ADR-0010).
//!
//! This module composes what the lower layers already provide and adds no
//! protocol behavior (docs/03-architecture.md §2). It deliberately mirrors
//! `kultd`'s daemon structure — the two are the same runtime with different
//! front doors, and a change to one almost always belongs in the other.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use rand::rngs::OsRng;
use rand::RngCore;
use tokio::sync::{mpsc, oneshot, watch};

use kult_crypto::{KdfProfile, SafetyNumber};
use kult_node::{
    AttachmentInfo, AttachmentMetadata, CallAudioFrame, CallAvailability, CallInfo,
    CarrierCapabilitySnapshot, ContactAuthorityConflictInfo, DeviceAuthorityConflictInfo,
    DeviceLinkSelection, Event, FolderConversationInfo, FolderConversationList, FolderInfo,
    FolderSelection, GroupAuthorityInfo, GroupInfo, GroupInvitationInfo, GroupMentionCapability,
    GroupRole, GroupSecurityInfo, LabelConversationInfo, LabelFilterInfo, LabelInfo,
    LabelMatchMode, LinkedDeviceInfo, MentionSpan, MessageDeviceDeliveryInfo, MessageRequestInfo,
    NativeWakeDestinationRegistration, Node, PinConversationList, PinInfo, ScheduledMessageInfo,
    StaleFolderInfo, StaleLabelInfo,
};
use kult_store::{ContactRecord, ConversationId, NoteMessageRecord, AUTHORITY_BACKUP_MAGIC};
use kult_transport::{
    DeliveryHint, Discovery, Libp2pTransport, MailboxConfig, MailboxServiceConfig, Transport,
    TransportOptions, MAX_MAILBOX_CHECKIN_TOKENS,
};

const MAX_MAILBOXES_PER_CHECKIN_TICK: usize = 8;
const MAX_MAILBOX_BACKOFF: Duration = Duration::from_secs(60 * 60);

#[derive(Clone, Copy)]
struct MailboxRetry {
    failures: u8,
    next_at: Instant,
}

fn rotating_batch<T: Clone>(items: &[T], cursor: &mut usize, limit: usize) -> Vec<T> {
    if items.is_empty() || limit == 0 {
        *cursor = 0;
        return Vec::new();
    }
    *cursor %= items.len();
    let end = cursor.saturating_add(limit).min(items.len());
    let batch = items[*cursor..end].to_vec();
    *cursor = if end == items.len() { 0 } else { end };
    batch
}

fn jittered_mailbox_delay(base: Duration, failures: u8, draw: u64) -> Duration {
    let multiplier = 1u32 << failures.min(6);
    let backed_off = base.saturating_mul(multiplier).min(MAX_MAILBOX_BACKOFF);
    let percent = 75u128 + u128::from(draw % 51);
    let millis = backed_off
        .as_millis()
        .saturating_mul(percent)
        .saturating_div(100)
        .max(250);
    Duration::from_millis(u64::try_from(millis).unwrap_or(u64::MAX))
}

/// A backup to restore from on first start (docs/07-storage.md §4).
#[derive(Clone)]
pub(crate) struct RestoreSource {
    /// The encrypted backup file's bytes.
    pub backup: Vec<u8>,
    /// The 24-word mnemonic sealing it.
    pub mnemonic: String,
    /// Separately held encrypted offline account authority.
    pub recovery_package: Vec<u8>,
    /// The separate 24-word phrase opening the recovery authority.
    pub recovery_mnemonic: String,
}

/// Everything the runtime needs, already validated and converted from the
/// FFI-facing [`crate::Config`].
#[derive(Clone)]
pub(crate) struct RuntimeConfig {
    pub db_path: PathBuf,
    pub passphrase: Vec<u8>,
    pub kdf: KdfProfile,
    pub mode: kult_transport::OperatingMode,
    pub public_mode: crate::NetworkMode,
    pub provider_directory: crate::ProviderDirectoryVerdict,
    pub discovery_policy: kult_node::DiscoveryPublicationPolicy,
    pub rendezvous: Vec<kult_transport::RendezvousProvider>,
    pub wake: Vec<kult_transport::WakeProvider>,
    pub tor_proxy: Option<std::net::SocketAddr>,
    pub fallback_ready: bool,
    /// Restore the store from a backup instead of creating a fresh
    /// identity. Refused when the store already exists.
    pub restore: Option<RestoreSource>,
    pub listen: Vec<String>,
    pub bootstrap: Vec<String>,
    pub relay: Option<String>,
    pub mailboxes: Vec<String>,
    pub serve_mailbox: bool,
    pub mdns: bool,
    pub spool: Option<PathBuf>,
    pub meshtastic_serial: Option<String>,
    pub meshtastic_tcp: Option<String>,
    pub bridge: bool,
    pub tick_interval: Duration,
    pub checkin_interval: Duration,
    pub nat_interval: Duration,
}

/// One typed reply channel. Errors are the node's own messages, verbatim —
/// nothing is downgraded to a fake success (implementation guide rule 4).
type Resp<T> = oneshot::Sender<Result<T, String>>;

/// What the actor task is asked to do. One variant per node operation the
/// FFI exposes — the typed equivalent of `kultd`'s wire ops.
pub(crate) enum Msg {
    ConnectCodeRotate {
        resp: Resp<String>,
    },
    ConnectCodeRetireLegacy {
        resp: Resp<String>,
    },
    DeviceId {
        resp: Resp<[u8; 32]>,
    },
    LinkedDevices {
        resp: Resp<Vec<LinkedDeviceInfo>>,
    },
    DeviceAuthorityConflicts {
        resp: Resp<Vec<DeviceAuthorityConflictInfo>>,
    },
    ContactAuthorityConflicts {
        resp: Resp<Vec<ContactAuthorityConflictInfo>>,
    },
    AuthorityResetHistory {
        resp: Resp<Option<kult_node::AuthorityResetHistoryRecord>>,
    },
    DeviceAuthorityApprovalRequest {
        resp: Resp<Vec<u8>>,
    },
    DeviceAuthorityApprove {
        request: Vec<u8>,
        resp: Resp<Vec<u8>>,
    },
    DeviceAuthorityAccept {
        approval: Vec<u8>,
        resp: Resp<bool>,
    },
    MessageDeviceDeliveries {
        message: [u8; 16],
        resp: Resp<Vec<MessageDeviceDeliveryInfo>>,
    },
    DeviceRename {
        device: [u8; 32],
        name: String,
        resp: Resp<()>,
    },
    DeviceRevoke {
        device: [u8; 32],
        resp: Resp<()>,
    },
    DeviceLinkBegin {
        resp: Resp<Vec<u8>>,
    },
    DeviceLinkAccept {
        offer: Vec<u8>,
        name: String,
        resp: Resp<(Vec<u8>, String)>,
    },
    DeviceLinkCode {
        response: Vec<u8>,
        resp: Resp<String>,
    },
    DeviceLinkApprove {
        response: Vec<u8>,
        selection: DeviceLinkSelection,
        confirmed: bool,
        resp: Resp<Vec<u8>>,
    },
    DeviceLinkApprovalRequest {
        resp: Resp<Vec<u8>>,
    },
    DeviceLinkApproveRequest {
        request: Vec<u8>,
        resp: Resp<Vec<u8>>,
    },
    DeviceLinkAcceptApproval {
        approval: Vec<u8>,
        resp: Resp<Option<Vec<u8>>>,
    },
    DeviceLinkComplete {
        package: Vec<u8>,
        confirmed: bool,
        resp: Resp<(String, [u8; 32])>,
    },
    DeviceSyncExport {
        device: [u8; 32],
        resp: Resp<Vec<u8>>,
    },
    DeviceSyncImport {
        bundle: Vec<u8>,
        resp: Resp<usize>,
    },
    AddContact {
        name: String,
        bundle: Vec<u8>,
        hints: Vec<DeliveryHint>,
        resp: Resp<[u8; 32]>,
    },
    AddByAddress {
        name: String,
        address: String,
        resp: Resp<[u8; 32]>,
    },
    AssessContactName {
        peer: [u8; 32],
        name: String,
        resp: Resp<kult_node::ContactNameAssessment>,
    },
    RenameContact {
        peer: [u8; 32],
        name: String,
        accept_warnings: bool,
        resp: Resp<kult_node::ContactNameAssessment>,
    },
    Send {
        peer: [u8; 32],
        body: Vec<u8>,
        resp: Resp<[u8; 16]>,
    },
    SendDisappearing {
        peer: [u8; 32],
        body: String,
        lifetime_secs: u64,
        resp: Resp<[u8; 16]>,
    },
    EditMessage {
        peer: [u8; 32],
        target_author: [u8; 32],
        target_content_id: [u8; 16],
        text: String,
        resp: Resp<[u8; 16]>,
    },
    AttachmentSend {
        peer: [u8; 32],
        metadata: AttachmentMetadata,
        path: PathBuf,
        preview: Option<(AttachmentMetadata, PathBuf)>,
        resp: Resp<[u8; 16]>,
    },
    AttachmentSendViewOnce {
        peer: [u8; 32],
        metadata: AttachmentMetadata,
        path: PathBuf,
        preview: Option<(AttachmentMetadata, PathBuf)>,
        lifetime_secs: u64,
        resp: Resp<[u8; 16]>,
    },
    GroupAttachmentSend {
        group: [u8; 32],
        metadata: AttachmentMetadata,
        path: PathBuf,
        preview: Option<(AttachmentMetadata, PathBuf)>,
        resp: Resp<[u8; 16]>,
    },
    GroupAttachmentSendViewOnce {
        group: [u8; 32],
        metadata: AttachmentMetadata,
        path: PathBuf,
        preview: Option<(AttachmentMetadata, PathBuf)>,
        lifetime_secs: u64,
        resp: Resp<[u8; 16]>,
    },
    Attachments {
        resp: Resp<Vec<AttachmentInfo>>,
    },
    AttachmentAccept {
        transfer: [u8; 16],
        resp: Resp<()>,
    },
    AttachmentReject {
        transfer: [u8; 16],
        resp: Resp<()>,
    },
    AttachmentCancel {
        transfer: [u8; 16],
        resp: Resp<()>,
    },
    AttachmentPause {
        transfer: [u8; 16],
        resp: Resp<()>,
    },
    AttachmentResume {
        transfer: [u8; 16],
        resp: Resp<()>,
    },
    AttachmentExport {
        transfer: [u8; 16],
        path: PathBuf,
        preview: bool,
        resp: Resp<()>,
    },
    AttachmentConsumeViewOnce {
        transfer: [u8; 16],
        path: PathBuf,
        resp: Resp<()>,
    },
    Schedule {
        peer: [u8; 32],
        body: Vec<u8>,
        not_before: u64,
        resp: Resp<[u8; 16]>,
    },
    GroupSchedule {
        group: [u8; 32],
        body: Vec<u8>,
        not_before: u64,
        resp: Resp<[u8; 16]>,
    },
    ScheduledEdit {
        id: [u8; 16],
        body: Vec<u8>,
        not_before: u64,
        resp: Resp<()>,
    },
    ScheduledCancel {
        id: [u8; 16],
        resp: Resp<()>,
    },
    ScheduledMessages {
        resp: Resp<Vec<ScheduledMessageInfo>>,
    },
    NoteToSelfSend {
        body: String,
        resp: Resp<[u8; 16]>,
    },
    NoteToSelfMessages {
        resp: Resp<Vec<NoteMessageRecord>>,
    },
    Theme {
        resp: Resp<(kult_node::ThemePreference, bool)>,
    },
    ThemeSet {
        preference: kult_node::ThemePreference,
        resp: Resp<bool>,
    },
    CustomIcon {
        target: kult_node::CustomIconTarget,
        resp: Resp<Option<kult_node::CustomIconInfo>>,
    },
    CustomIconSetPath {
        target: kult_node::CustomIconTarget,
        path: PathBuf,
        crop: Option<kult_node::CustomIconCrop>,
        resp: Resp<kult_node::CustomIconInfo>,
    },
    CustomIconSetBundled {
        target: kult_node::CustomIconTarget,
        glyph: String,
        resp: Resp<kult_node::CustomIconInfo>,
    },
    CustomIconClear {
        target: kult_node::CustomIconTarget,
        resp: Resp<bool>,
    },
    CustomIconUsage {
        resp: Resp<kult_node::CustomIconUsage>,
    },
    FolderCreate {
        name: String,
        resp: Resp<FolderInfo>,
    },
    Folders {
        resp: Resp<Vec<FolderInfo>>,
    },
    FolderGet {
        folder: [u8; 16],
        resp: Resp<FolderInfo>,
    },
    FolderRename {
        folder: [u8; 16],
        name: String,
        resp: Resp<FolderInfo>,
    },
    FolderReorder {
        folders: Vec<[u8; 16]>,
        resp: Resp<Vec<FolderInfo>>,
    },
    FolderDeletePreview {
        folder: [u8; 16],
        resp: Resp<usize>,
    },
    FolderDelete {
        folder: [u8; 16],
        resp: Resp<usize>,
    },
    FolderMove {
        folder: [u8; 16],
        target: ConversationId,
        resp: Resp<bool>,
    },
    FolderUnfile {
        target: ConversationId,
        resp: Resp<bool>,
    },
    FolderMembership {
        folder: [u8; 16],
        resp: Resp<Vec<FolderConversationInfo>>,
    },
    ConversationFolder {
        target: ConversationId,
        resp: Resp<Option<FolderInfo>>,
    },
    FolderConversations {
        selection: FolderSelection,
        labels: Vec<[u8; 16]>,
        mode: LabelMatchMode,
        resp: Resp<FolderConversationList>,
    },
    FolderStale {
        resp: Resp<Vec<StaleFolderInfo>>,
    },
    FolderStaleCleanup {
        folder: [u8; 16],
        target: ConversationId,
        resp: Resp<bool>,
    },
    LabelCreate {
        name: String,
        color: String,
        resp: Resp<LabelInfo>,
    },
    Labels {
        resp: Resp<Vec<LabelInfo>>,
    },
    LabelGet {
        label: [u8; 16],
        resp: Resp<LabelInfo>,
    },
    LabelUpdate {
        label: [u8; 16],
        name: String,
        color: String,
        resp: Resp<LabelInfo>,
    },
    LabelDeletePreview {
        label: [u8; 16],
        resp: Resp<usize>,
    },
    LabelDelete {
        label: [u8; 16],
        resp: Resp<usize>,
    },
    LabelAssign {
        label: [u8; 16],
        target: ConversationId,
        resp: Resp<bool>,
    },
    LabelUnassign {
        label: [u8; 16],
        target: ConversationId,
        resp: Resp<bool>,
    },
    LabelMembership {
        label: [u8; 16],
        resp: Resp<Vec<LabelConversationInfo>>,
    },
    LabelsForConversation {
        target: ConversationId,
        resp: Resp<Vec<LabelInfo>>,
    },
    LabelStale {
        resp: Resp<Vec<StaleLabelInfo>>,
    },
    LabelStaleCleanup {
        label: [u8; 16],
        target: ConversationId,
        resp: Resp<bool>,
    },
    LabelFilter {
        labels: Vec<[u8; 16]>,
        mode: LabelMatchMode,
        resp: Resp<LabelFilterInfo>,
    },
    Pin {
        target: ConversationId,
        resp: Resp<bool>,
    },
    Unpin {
        target: ConversationId,
        resp: Resp<bool>,
    },
    PinState {
        target: ConversationId,
        resp: Resp<Option<PinInfo>>,
    },
    Pins {
        resp: Resp<Vec<PinInfo>>,
    },
    PinReorder {
        targets: Vec<ConversationId>,
        resp: Resp<Vec<PinInfo>>,
    },
    PinStale {
        resp: Resp<Vec<PinInfo>>,
    },
    PinStaleCleanup {
        target: ConversationId,
        resp: Resp<bool>,
    },
    PinConversations {
        selection: FolderSelection,
        labels: Vec<[u8; 16]>,
        mode: LabelMatchMode,
        resp: Resp<PinConversationList>,
    },
    GroupCreate {
        name: String,
        members: Vec<[u8; 32]>,
        resp: Resp<[u8; 32]>,
    },
    GroupSecurity {
        group: [u8; 32],
        resp: Resp<GroupSecurityInfo>,
    },
    GroupUpgradeSecurity {
        group: [u8; 32],
        resp: Resp<()>,
    },
    GroupSend {
        group: [u8; 32],
        body: Vec<u8>,
        resp: Resp<[u8; 16]>,
    },
    GroupSendDisappearing {
        group: [u8; 32],
        body: String,
        lifetime_secs: u64,
        resp: Resp<[u8; 16]>,
    },
    GroupEditMessage {
        group: [u8; 32],
        target_author: [u8; 32],
        target_content_id: [u8; 16],
        text: String,
        resp: Resp<[u8; 16]>,
    },
    GroupMentionCapability {
        group: [u8; 32],
        resp: Resp<GroupMentionCapability>,
    },
    GroupMentionSend {
        group: [u8; 32],
        text: String,
        spans: Vec<MentionSpan>,
        review_token: [u8; 16],
        resp: Resp<[u8; 16]>,
    },
    GroupPollCreate {
        group: [u8; 32],
        question: String,
        options: Vec<String>,
        resp: Resp<[u8; 16]>,
    },
    GroupPolls {
        group: [u8; 32],
        resp: Resp<Vec<kult_node::PollInfo>>,
    },
    GroupPollVote {
        group: [u8; 32],
        poll_author: [u8; 32],
        poll_id: [u8; 16],
        option_id: [u8; 16],
        resp: Resp<[u8; 16]>,
    },
    GroupPollClose {
        group: [u8; 32],
        poll_author: [u8; 32],
        poll_id: [u8; 16],
        resp: Resp<[u8; 16]>,
    },
    GroupPollModerateClose {
        group: [u8; 32],
        poll_author: [u8; 32],
        poll_id: [u8; 16],
        resp: Resp<[u8; 16]>,
    },
    GroupAuthority {
        group: [u8; 32],
        resp: Resp<GroupAuthorityInfo>,
    },
    GroupUpgradeAuthority {
        group: [u8; 32],
        resp: Resp<[u8; 16]>,
    },
    GroupRename {
        group: [u8; 32],
        name: String,
        resp: Resp<[u8; 16]>,
    },
    GroupSetRole {
        group: [u8; 32],
        peer: [u8; 32],
        role: GroupRole,
        resp: Resp<[u8; 16]>,
    },
    GroupTransferOwner {
        group: [u8; 32],
        peer: [u8; 32],
        resp: Resp<[u8; 16]>,
    },
    GroupAdd {
        group: [u8; 32],
        peer: [u8; 32],
        resp: Resp<()>,
    },
    GroupRemove {
        group: [u8; 32],
        peer: [u8; 32],
        resp: Resp<()>,
    },
    GroupLeave {
        group: [u8; 32],
        resp: Resp<()>,
    },
    GroupInvitations {
        resp: Resp<Vec<GroupInvitationInfo>>,
    },
    GroupInvitationAccept {
        invitation: [u8; 16],
        resp: Resp<[u8; 32]>,
    },
    GroupInvitationDelete {
        invitation: [u8; 16],
        resp: Resp<()>,
    },
    Groups {
        resp: Resp<Vec<GroupInfo>>,
    },
    GroupMessages {
        group: [u8; 32],
        resp: Resp<Vec<kult_node::ResolvedGroupMessage>>,
    },
    Contacts {
        resp: Resp<Vec<ContactRecord>>,
    },
    MessageRequests {
        resp: Resp<Vec<MessageRequestInfo>>,
    },
    MessageRequestAccept {
        request: [u8; 16],
        name: String,
        resp: Resp<[u8; 32]>,
    },
    MessageRequestDelete {
        request: [u8; 16],
        resp: Resp<()>,
    },
    MessageRequestBlock {
        request: [u8; 16],
        resp: Resp<()>,
    },
    CarrierCapabilities {
        resp: Resp<Vec<CarrierCapabilitySnapshot>>,
    },
    Calls {
        resp: Resp<Vec<CallInfo>>,
    },
    CallAvailability {
        peer: [u8; 32],
        resp: Resp<CallAvailability>,
    },
    CallStart {
        peer: [u8; 32],
        resp: Resp<[u8; 16]>,
    },
    CallAnswer {
        call: [u8; 16],
        resp: Resp<()>,
    },
    CallDecline {
        call: [u8; 16],
        resp: Resp<()>,
    },
    CallCancel {
        call: [u8; 16],
        resp: Resp<()>,
    },
    CallHangup {
        call: [u8; 16],
        resp: Resp<()>,
    },
    CallAudioSend {
        call: [u8; 16],
        timestamp_ms: u64,
        opus_packet: Vec<u8>,
        resp: Resp<bool>,
    },
    CallAudioTake {
        call: [u8; 16],
        resp: Resp<Option<CallAudioFrame>>,
    },
    Messages {
        peer: [u8; 32],
        resp: Resp<Vec<kult_node::ResolvedMessage>>,
    },
    SafetyNumber {
        peer: [u8; 32],
        resp: Resp<SafetyNumber>,
    },
    MarkVerified {
        peer: [u8; 32],
        resp: Resp<()>,
    },
    SetHints {
        peer: [u8; 32],
        hints: Vec<DeliveryHint>,
        resp: Resp<()>,
    },
    RendezvousRefresh {
        peer: [u8; 32],
        resp: Resp<()>,
    },
    RendezvousConversationActive {
        peer: [u8; 32],
        active: bool,
        resp: Resp<()>,
    },
    Publish {
        resp: Resp<()>,
    },
    Backup {
        path: PathBuf,
        resp: Resp<String>,
    },
    RecoveryAuthorityExport {
        path: PathBuf,
        resp: Resp<String>,
    },
    RefreshHandshakeBundle {
        cache: Arc<Mutex<PairingBundleCache>>,
    },
    Tokens {
        resp: oneshot::Sender<Vec<[u8; 32]>>,
    },
    WakeCollect {
        budget_ms: u32,
        resp: Resp<u32>,
    },
    WakeRegister {
        platform: kult_protocol::WakePlatform,
        environment: kult_protocol::WakeEnvironment,
        profile: kult_protocol::WakeProfile,
        provider_token: Vec<u8>,
        app_topic: Vec<u8>,
        resp: Resp<kult_node::NativeWakeRegistrationResult>,
    },
    WakeRevoke {
        resp: Resp<usize>,
    },
    BridgeRelays(Vec<DeliveryHint>),
}

/// Queue depths and contact count for the status report.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Counts {
    pub queued: u64,
    pub scheduled: u64,
    pub transit: u64,
    pub contacts: u64,
}

pub(crate) struct PairingBundleCache {
    current: Vec<u8>,
    refresh_pending: bool,
}

struct ActorCaches {
    counts: Arc<Mutex<Counts>>,
    discovery: Arc<Mutex<(String, bool)>>,
}

/// A running embedded node. Owns its tokio runtime; every task stops on
/// [`Runtime::stop`] (or best-effort on drop).
pub(crate) struct Runtime {
    pub address: String,
    pub peer: [u8; 32],
    pub tx: mpsc::Sender<Msg>,
    pub net: Arc<Libp2pTransport>,
    pub mode: crate::NetworkMode,
    pub provider_directory: crate::ProviderDirectoryVerdict,
    pub fallback_ready: bool,
    counts: Arc<Mutex<Counts>>,
    discovery: Arc<Mutex<(String, bool)>>,
    pairing_bundle: Arc<Mutex<PairingBundleCache>>,
    rt: tokio::runtime::Runtime,
    shutdown: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    dispatcher: Option<std::thread::JoinHandle<()>>,
}

impl Runtime {
    /// Open (or create) the node, attach the configured carriers, and start
    /// the actor, lifecycle, and event-dispatch tasks. Blocking: Argon2id
    /// key derivation and transport binding happen before this returns, so
    /// a wrong passphrase or unreachable radio is a startup error, not a
    /// broken half-running node.
    pub(crate) fn start(
        cfg: RuntimeConfig,
        listener: Box<dyn Fn(Event) + Send>,
    ) -> Result<Self, String> {
        let node = if let Some(restore) = &cfg.restore {
            // Restore is a first-run operation: an existing store holds an
            // identity, and silently replacing it would destroy keys.
            if cfg.db_path.exists() {
                return Err(format!(
                    "refusing to restore over the existing store {}",
                    cfg.db_path.display()
                ));
            }
            if restore.backup.starts_with(&AUTHORITY_BACKUP_MAGIC) {
                Node::restore_with_recovery_authority(
                    &cfg.db_path,
                    &restore.backup,
                    &restore.mnemonic,
                    &restore.recovery_package,
                    &restore.recovery_mnemonic,
                    now(),
                    &cfg.passphrase,
                    cfg.kdf,
                    &mut OsRng,
                )
            } else {
                Node::restore_legacy_backup_with_authority_reset(
                    &cfg.db_path,
                    &restore.backup,
                    &restore.mnemonic,
                    &restore.recovery_package,
                    &restore.recovery_mnemonic,
                    now(),
                    &cfg.passphrase,
                    cfg.kdf,
                    &mut OsRng,
                )
            }
        } else if cfg.db_path.exists() {
            Node::open(&cfg.db_path, &cfg.passphrase)
        } else {
            Node::create(&cfg.db_path, &cfg.passphrase, cfg.kdf, &mut OsRng)
        }
        .map_err(|e| format!("store: {e}"))?;
        Self::start_node(cfg, node, listener)
    }

    /// Complete an explicit single-device Alpha authority migration and keep
    /// the same unlocked store handle while the ordinary runtime starts.
    pub(crate) fn migrate_authority(
        cfg: RuntimeConfig,
        recovery_package: &[u8],
        recovery_mnemonic: &str,
        listener: Box<dyn Fn(Event) + Send>,
    ) -> Result<Self, String> {
        if !cfg.db_path.exists() {
            return Err(format!(
                "authority migration requires the existing store {}",
                cfg.db_path.display()
            ));
        }
        let node = Node::complete_authority_migration(
            &cfg.db_path,
            &cfg.passphrase,
            recovery_package,
            recovery_mnemonic,
            now(),
            &mut OsRng,
        )
        .map_err(|e| format!("store: {e}"))?;
        Self::start_node(cfg, node, listener)
    }

    /// Complete an explicit copied-root Alpha reset and keep the newly
    /// replaced store handle while the ordinary runtime starts.
    pub(crate) fn reset_authority(
        cfg: RuntimeConfig,
        recovery_package: &[u8],
        recovery_mnemonic: &str,
        listener: Box<dyn Fn(Event) + Send>,
    ) -> Result<Self, String> {
        if !cfg.db_path.exists() {
            return Err(format!(
                "authority reset requires the existing store {}",
                cfg.db_path.display()
            ));
        }
        let node = Node::complete_authority_reset(
            &cfg.db_path,
            &cfg.passphrase,
            recovery_package,
            recovery_mnemonic,
            now(),
            &mut OsRng,
        )
        .map_err(|e| format!("store: {e}"))?;
        Self::start_node(cfg, node, listener)
    }

    fn start_node(
        cfg: RuntimeConfig,
        mut node: Node,
        listener: Box<dyn Fn(Event) + Send>,
    ) -> Result<Self, String> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| format!("runtime: {e}"))?;

        // Bridging needs both sides: it activates only when a radio is
        // configured (and startup fails hard if that radio is unreachable,
        // so "bridging" is never claimed without a mesh).
        let bridging =
            cfg.bridge && (cfg.meshtastic_serial.is_some() || cfg.meshtastic_tcp.is_some());
        let net = {
            let listen: Vec<&str> = cfg.listen.iter().map(String::as_str).collect();
            let mailbox_dir = cfg.db_path.parent().unwrap_or_else(|| Path::new("."));
            let options = TransportOptions {
                mailbox: cfg.serve_mailbox.then(|| {
                    MailboxServiceConfig::in_directory(mailbox_dir, MailboxConfig::default())
                }),
                lan_discovery: cfg.mdns,
                bridge_deposits: bridging,
            };
            rt.block_on(Libp2pTransport::with_options(&listen, options))
                .map_err(|e| format!("internet transport: {e}"))?
        };
        let net = Arc::new(net);
        node.add_transport(Arc::clone(&net) as Arc<dyn Transport>);
        node.add_discovery(Arc::clone(&net) as Arc<dyn Discovery>);
        if let Some(spool) = &cfg.spool {
            let sneaker = kult_transport::SneakernetTransport::new(spool)
                .map_err(|e| format!("spool: {e}"))?;
            node.add_transport(Arc::new(sneaker));
        }
        // A radio that was asked for but cannot be reached is a hard startup
        // error, same contract as kultd: silently running without the
        // configured off-grid carrier would be a lie about coverage.
        #[cfg(feature = "meshtastic")]
        {
            use kult_transport::{MeshtasticOptions, MeshtasticTransport};
            if let Some(port) = &cfg.meshtastic_serial {
                let radio = rt
                    .block_on(MeshtasticTransport::connect_serial(
                        port,
                        None,
                        MeshtasticOptions::default(),
                    ))
                    .map_err(|e| format!("meshtastic serial {port}: {e}"))?;
                node.add_transport(Arc::new(radio));
            }
            if let Some(addr) = &cfg.meshtastic_tcp {
                let radio = rt
                    .block_on(MeshtasticTransport::connect_tcp(
                        addr,
                        MeshtasticOptions::default(),
                    ))
                    .map_err(|e| format!("meshtastic tcp {addr}: {e}"))?;
                node.add_transport(Arc::new(radio));
            }
        }
        #[cfg(not(feature = "meshtastic"))]
        if cfg.meshtastic_serial.is_some() || cfg.meshtastic_tcp.is_some() {
            return Err(
                "this build has no Meshtastic support (enable kult-ffi's `meshtastic` feature)"
                    .to_owned(),
            );
        }
        if bridging {
            node.set_bridge(Some(bridge_relays(&cfg, None)));
        }
        let rendezvous_client: Option<Arc<dyn kult_transport::RendezvousClient>> =
            if cfg.rendezvous.is_empty() {
                None
            } else {
                Some(match cfg.mode {
                    kult_transport::OperatingMode::Standard => {
                        Arc::new(kult_transport::HttpsRendezvousClient::direct())
                    }
                    kult_transport::OperatingMode::Private => Arc::new(
                        kult_transport::HttpsRendezvousClient::tor(
                            cfg.tor_proxy
                                .ok_or_else(|| "Private rendezvous has no Tor proxy".to_owned())?,
                        )
                        .map_err(|error| format!("Tor rendezvous: {error}"))?,
                    ),
                    kult_transport::OperatingMode::Sovereign => {
                        return Err("Sovereign mode cannot configure rendezvous".to_owned())
                    }
                })
            };
        node.reconcile_rendezvous(
            cfg.discovery_policy.mode,
            rendezvous_client,
            cfg.rendezvous.clone(),
        )
        .map_err(|error| format!("rendezvous configuration: {error}"))?;
        let wake_client: Option<Arc<dyn kult_transport::WakeClient>> = match cfg.mode {
            kult_transport::OperatingMode::Standard => {
                Some(Arc::new(kult_transport::HttpsWakeClient::direct()))
            }
            kult_transport::OperatingMode::Private => match cfg.tor_proxy {
                Some(proxy) => Some(Arc::new(
                    kult_transport::HttpsWakeClient::tor(proxy)
                        .map_err(|error| format!("Tor native wake: {error}"))?,
                )),
                // Native wake is optional. Without an anonymizing ingress,
                // Private mode leaves it disabled instead of falling back to
                // a direct request or blocking ordinary delivery.
                None => None,
            },
            kult_transport::OperatingMode::Sovereign => None,
        };
        node.configure_wake(cfg.discovery_policy.mode, wake_client)
            .map_err(|error| format!("native-wake configuration: {error}"))?;
        node.reconcile_wake_providers(&cfg.wake, now(), &mut OsRng)
            .map_err(|error| format!("native-wake provider reconciliation: {error}"))?;

        let address = node.address();
        let peer = node.peer_id();
        let counts = Arc::new(Mutex::new(snapshot_counts(&node).unwrap_or_default()));
        let discovery = Arc::new(Mutex::new((
            node.connect_code()
                .map_err(|error| format!("connect code: {error}"))?,
            node.legacy_discovery_enabled(),
        )));
        // A scanned bundle must contain a usable first-message route. Wait
        // for libp2p's asynchronous listener event before signing the ready
        // bundle; failure leaves mailbox-only/off-grid configurations usable.
        let _ = rt.block_on(net.wait_listen_addr());
        let initial_pairing_hints = own_hints(&net, &cfg.mailboxes);
        // Keep one fresh pairing bundle outside the actor. UI sharing must
        // not queue behind a slow delivery retry; taking it asks the actor
        // to replenish the next bundle in the background.
        let pairing_bundle = Arc::new(Mutex::new(PairingBundleCache {
            current: node
                .handshake_bundle_with_hints(&initial_pairing_hints, now(), &mut OsRng)
                .map_err(|error| format!("pairing bundle: {error}"))?,
            refresh_pending: false,
        }));

        let (shutdown, _) = watch::channel(false);
        let (tx, rx) = mpsc::channel::<Msg>(64);
        let (events_tx, mut events_rx) = mpsc::unbounded_channel::<Event>();

        let mut tasks = Vec::new();
        // The node's store is single-threaded by design (one SQLite
        // connection), so its futures are not `Send`: the actor gets its
        // own current-thread runtime on a blocking thread, exactly like
        // kultd's daemon. Channels bridge the two runtimes safely.
        let actor_inputs = (
            cfg.clone(),
            Arc::clone(&net),
            ActorCaches {
                counts: Arc::clone(&counts),
                discovery: Arc::clone(&discovery),
            },
            events_tx,
            shutdown.subscribe(),
        );
        tasks.push(rt.spawn_blocking(move || {
            let (cfg, net, caches, events, shutdown) = actor_inputs;
            let local = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("actor runtime");
            local.block_on(actor(node, cfg, net, caches, rx, events, shutdown));
        }));
        tasks.push(rt.spawn(lifecycle(
            cfg.clone(),
            Arc::clone(&net),
            tx.clone(),
            shutdown.subscribe(),
        )));
        // The listener runs on its own plain thread: a callback into
        // application code may block, and must never stall the tick loop or
        // a tokio worker. Exits when the actor (sole sender) does.
        let dispatcher = std::thread::spawn(move || {
            while let Some(event) = events_rx.blocking_recv() {
                listener(event);
            }
        });

        Ok(Self {
            address,
            peer,
            tx,
            net,
            mode: cfg.public_mode,
            provider_directory: cfg.provider_directory,
            fallback_ready: cfg.fallback_ready,
            counts,
            discovery,
            pairing_bundle,
            rt,
            shutdown,
            tasks,
            dispatcher: Some(dispatcher),
        })
    }

    /// Run a future on this runtime from a foreign (non-tokio) thread.
    pub(crate) fn block_on<F: std::future::Future>(&self, fut: F) -> F::Output {
        self.rt.block_on(fut)
    }

    /// Latest local queue/contact counts, never blocked behind network work.
    pub(crate) fn counts(&self) -> Counts {
        *self
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Current capability-scoped share code and legacy bridge state.
    pub(crate) fn discovery(&self) -> (String, bool) {
        self.discovery
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn set_discovery(&self, connect_code: String, legacy: bool) {
        *self
            .discovery
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = (connect_code, legacy);
    }

    /// Return the ready pairing bundle and refresh it asynchronously.
    ///
    /// Repeated reads while the actor is busy return the same still-valid
    /// bundle instead of blocking the UI or minting wasteful OPK pools.
    pub(crate) fn pairing_bundle(&self) -> Vec<u8> {
        let mut cache = self
            .pairing_bundle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let bundle = cache.current.clone();
        if cache.refresh_pending {
            return bundle;
        }
        cache.refresh_pending = true;
        drop(cache);
        if self
            .tx
            .try_send(Msg::RefreshHandshakeBundle {
                cache: Arc::clone(&self.pairing_bundle),
            })
            .is_err()
        {
            self.pairing_bundle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .refresh_pending = false;
        }
        bundle
    }

    /// Stop every task and wait for them.
    pub(crate) fn stop(mut self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks.drain(..) {
            let _ = self.rt.block_on(task);
        }
        if let Some(dispatcher) = self.dispatcher.take() {
            let _ = dispatcher.join();
        }
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod lifecycle_tests {
    use super::*;

    #[test]
    fn rotating_batches_bound_work_and_cover_every_entry() {
        let items = (0..17).collect::<Vec<_>>();
        let mut cursor = 0;
        let first = rotating_batch(&items, &mut cursor, 8);
        let second = rotating_batch(&items, &mut cursor, 8);
        let third = rotating_batch(&items, &mut cursor, 8);
        assert_eq!(first, (0..8).collect::<Vec<_>>());
        assert_eq!(second, (8..16).collect::<Vec<_>>());
        assert_eq!(third, vec![16]);
        assert_eq!(cursor, 0);
    }

    #[test]
    fn mailbox_backoff_is_jittered_exponential_and_bounded() {
        let base = Duration::from_secs(10);
        assert_eq!(
            jittered_mailbox_delay(base, 0, 0),
            Duration::from_millis(7_500)
        );
        assert_eq!(
            jittered_mailbox_delay(base, 0, 50),
            Duration::from_millis(12_500)
        );
        assert!(jittered_mailbox_delay(base, 4, 25) > jittered_mailbox_delay(base, 3, 25));
        assert!(
            jittered_mailbox_delay(Duration::from_secs(3_600), u8::MAX, 50)
                <= MAX_MAILBOX_BACKOFF.saturating_mul(5) / 4
        );
    }
}

impl Drop for Runtime {
    /// Best-effort shutdown signal, so dropping without [`Runtime::stop`]
    /// (an application that forgot) still lets the tokio runtime's own drop
    /// — which waits for blocking tasks — terminate rather than hang.
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Write a secret-bearing file: created 0600 from the first byte, and an
/// existing file is never overwritten (pick a new name or remove it first).
/// Kept in lockstep with `kultd`'s equivalent.
fn write_private(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    open_private(path)?.write_all(bytes)
}

/// Create a protected caller-selected destination without overwriting.
fn open_private(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// The hints this node publishes: every live listen address (circuit
/// addresses included once reserved) plus each mailbox relay it collects
/// from.
fn own_hints(net: &Libp2pTransport, mailboxes: &[String]) -> Vec<DeliveryHint> {
    let mut hints: Vec<DeliveryHint> = net
        .listen_addrs()
        .into_iter()
        .map(DeliveryHint::Multiaddr)
        .collect();
    hints.extend(mailboxes.iter().cloned().map(DeliveryHint::Relay));
    hints
}

/// The internet-side deposit targets for mesh-heard transit (ADR-0009):
/// the configured mailbox relays, plus this node's own mailbox service
/// (as a relay hint on its own listen address) once one is bound.
fn bridge_relays(cfg: &RuntimeConfig, own_addr: Option<&str>) -> Vec<DeliveryHint> {
    let mut relays: Vec<DeliveryHint> = cfg
        .mailboxes
        .iter()
        .cloned()
        .map(DeliveryHint::Relay)
        .collect();
    if cfg.serve_mailbox {
        if let Some(addr) = own_addr {
            relays.push(DeliveryHint::Relay(addr.to_owned()));
        }
    }
    relays
}

/// The actor task: sole owner of the [`Node`]. Alternates between serving
/// channel messages and the delivery-engine heartbeat.
async fn actor(
    mut node: Node,
    cfg: RuntimeConfig,
    net: Arc<Libp2pTransport>,
    caches: ActorCaches,
    mut rx: mpsc::Receiver<Msg>,
    events: mpsc::UnboundedSender<Event>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut tick = tokio::time::interval(cfg.tick_interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut media_tick = tokio::time::interval(Duration::from_millis(20));
    media_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut discovery_retry_at = tokio::time::Instant::now();
    loop {
        let mut check_discovery = false;
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            msg = rx.recv() => {
                match msg {
                    None => break,
                    Some(msg) => handle(&mut node, &cfg, &net, &events, msg).await,
                }
            }
            _ = tick.tick() => {
                check_discovery = true;
                match node.tick(now(), &mut OsRng).await {
                    Ok(batch) => {
                        for event in batch {
                            let _ = events.send(event);
                        }
                    }
                    Err(e) => eprintln!("kult-ffi: tick failed: {e}"),
                }
            }
            _ = media_tick.tick() => {
                if let Err(e) = node.pump_call_media(now()).await {
                    eprintln!("kult-ffi: call media pump failed: {e}");
                }
                for event in node.drain_events() {
                    let _ = events.send(event);
                }
            }
        }
        let discovery_now = tokio::time::Instant::now();
        if check_discovery && discovery_now >= discovery_retry_at {
            let hints = own_hints(&net, &cfg.mailboxes);
            if node
                .discovery_publication_needed_with_policy(&hints, cfg.discovery_policy)
                .unwrap_or(false)
            {
                match node
                    .publish_bundle_with_policy(&hints, cfg.discovery_policy, now())
                    .await
                {
                    Ok(()) => discovery_retry_at = discovery_now,
                    Err(error) => {
                        eprintln!("kult-ffi: discovery refresh failed: {error}");
                        discovery_retry_at = discovery_now + std::time::Duration::from_secs(60);
                    }
                }
            }
        }
        if let Some(snapshot) = snapshot_counts(&node) {
            *caches
                .counts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = snapshot;
        }
        if let Ok(connect_code) = node.connect_code() {
            *caches
                .discovery
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                (connect_code, node.legacy_discovery_enabled());
        }
    }
}

fn snapshot_counts(node: &Node) -> Option<Counts> {
    Some(Counts {
        queued: node.queued().ok()? as u64,
        scheduled: node.scheduled_messages().ok()?.len() as u64,
        transit: node.transit_queued() as u64,
        contacts: node.contacts().ok()?.len() as u64,
    })
}

/// Execute one operation against the node.
async fn handle(
    node: &mut Node,
    cfg: &RuntimeConfig,
    net: &Libp2pTransport,
    events: &mpsc::UnboundedSender<Event>,
    msg: Msg,
) {
    let now = now();
    let fail = |e: kult_node::NodeError| e.to_string();
    match msg {
        Msg::ConnectCodeRotate { resp } => {
            let result = match node.rotate_connect_code(&mut OsRng).map_err(fail) {
                Ok(connect_code) => {
                    let hints = own_hints(net, &cfg.mailboxes);
                    let _ = node
                        .publish_bundle_with_policy(&hints, cfg.discovery_policy, now)
                        .await;
                    Ok(connect_code)
                }
                Err(error) => Err(error),
            };
            let _ = resp.send(result);
        }
        Msg::ConnectCodeRetireLegacy { resp } => {
            let result = node.retire_legacy_discovery(&mut OsRng).map_err(fail);
            let result = match result {
                Ok(()) => {
                    let hints = own_hints(net, &cfg.mailboxes);
                    let _ = node
                        .publish_bundle_with_policy(&hints, cfg.discovery_policy, now)
                        .await;
                    node.connect_code().map_err(fail)
                }
                Err(error) => Err(error),
            };
            let _ = resp.send(result);
        }
        Msg::DeviceId { resp } => {
            let _ = resp.send(Ok(node.device_id()));
        }
        Msg::LinkedDevices { resp } => {
            let _ = resp.send(Ok(node.linked_devices()));
        }
        Msg::DeviceAuthorityConflicts { resp } => {
            let _ = resp.send(Ok(node.device_authority_conflicts()));
        }
        Msg::ContactAuthorityConflicts { resp } => {
            let _ = resp.send(node.contact_authority_conflicts().map_err(fail));
        }
        Msg::AuthorityResetHistory { resp } => {
            let _ = resp.send(node.authority_reset_history().map_err(fail));
        }
        Msg::DeviceAuthorityApprovalRequest { resp } => {
            let _ = resp.send(node.device_authority_approval_request().map_err(fail));
        }
        Msg::DeviceAuthorityApprove { request, resp } => {
            let _ = resp.send(
                node.approve_device_authority_request(&request)
                    .map_err(fail),
            );
        }
        Msg::DeviceAuthorityAccept { approval, resp } => {
            let _ = resp.send(
                node.accept_device_authority_approval(&approval, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::MessageDeviceDeliveries { message, resp } => {
            let _ = resp.send(node.message_device_deliveries(&message).map_err(fail));
        }
        Msg::DeviceRename { device, name, resp } => {
            let _ = resp.send(
                node.rename_linked_device(&device, &name, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::DeviceRevoke { device, resp } => {
            let _ = resp.send(
                node.revoke_linked_device(&device, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::DeviceLinkBegin { resp } => {
            let _ = resp.send(node.begin_device_link(now, &mut OsRng).map_err(fail));
        }
        Msg::DeviceLinkAccept { offer, name, resp } => {
            let _ = resp.send(
                node.accept_device_link(&offer, &name, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::DeviceLinkCode { response, resp } => {
            let _ = resp.send(node.device_link_confirmation_code(&response).map_err(fail));
        }
        Msg::DeviceLinkApprove {
            response,
            selection,
            confirmed,
            resp,
        } => {
            let _ = resp.send(
                node.approve_device_link(&response, selection, confirmed, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::DeviceLinkComplete {
            package,
            confirmed,
            resp,
        } => {
            let result = node
                .complete_device_link(&package, confirmed, now, &mut OsRng)
                .map(|()| (node.address(), node.peer_id()))
                .map_err(fail);
            let _ = resp.send(result);
        }
        Msg::DeviceSyncExport { device, resp } => {
            let _ = resp.send(node.export_device_sync(&device, &mut OsRng).map_err(fail));
        }
        Msg::DeviceSyncImport { bundle, resp } => {
            let _ = resp.send(node.import_device_sync(&bundle, &mut OsRng).map_err(fail));
        }
        Msg::AddContact {
            name,
            bundle,
            hints,
            resp,
        } => {
            let _ = resp.send(
                node.add_contact(&name, &bundle, &hints, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::AddByAddress {
            name,
            address,
            resp,
        } => {
            let _ = resp.send(
                node.add_contact_by_address(&name, &address, now, &mut OsRng)
                    .await
                    .map_err(fail),
            );
        }
        Msg::AssessContactName { peer, name, resp } => {
            let _ = resp.send(node.assess_contact_name(&peer, &name).map_err(fail));
        }
        Msg::RenameContact {
            peer,
            name,
            accept_warnings,
            resp,
        } => {
            let _ = resp.send(
                node.rename_contact(&peer, &name, accept_warnings, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::Send { peer, body, resp } => {
            let _ = resp.send(
                node.send_message(&peer, &body, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::SendDisappearing {
            peer,
            body,
            lifetime_secs,
            resp,
        } => {
            let _ = resp.send(
                node.send_disappearing_message(&peer, &body, lifetime_secs, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::EditMessage {
            peer,
            target_author,
            target_content_id,
            text,
            resp,
        } => {
            let _ = resp.send(
                node.edit_message(
                    &peer,
                    target_author,
                    target_content_id,
                    &text,
                    now,
                    &mut OsRng,
                )
                .map_err(fail),
            );
        }
        Msg::DeviceLinkApprovalRequest { resp } => {
            let _ = resp.send(node.device_link_approval_request().map_err(fail));
        }
        Msg::DeviceLinkApproveRequest { request, resp } => {
            let _ = resp.send(node.approve_device_link_request(&request).map_err(fail));
        }
        Msg::DeviceLinkAcceptApproval { approval, resp } => {
            let _ = resp.send(
                node.accept_device_link_approval(&approval, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::AttachmentSend {
            peer,
            metadata,
            path,
            preview,
            resp,
        } => {
            let result = std::fs::File::open(path)
                .map_err(|e| format!("attachment source: {e}"))
                .and_then(|mut source| {
                    let mut opened_preview = match preview {
                        Some((preview_metadata, path)) => Some((
                            preview_metadata,
                            std::fs::File::open(path)
                                .map_err(|e| format!("attachment preview source: {e}"))?,
                        )),
                        None => None,
                    };
                    let preview = opened_preview
                        .as_mut()
                        .map(|(metadata, source)| (&*metadata, source));
                    node.send_attachment_with_preview(
                        &peer,
                        &metadata,
                        &mut source,
                        preview,
                        now,
                        &mut OsRng,
                    )
                    .map_err(fail)
                });
            let _ = resp.send(result);
        }
        Msg::AttachmentSendViewOnce {
            peer,
            metadata,
            path,
            preview,
            lifetime_secs,
            resp,
        } => {
            let result = std::fs::File::open(path)
                .map_err(|e| format!("attachment source: {e}"))
                .and_then(|mut source| {
                    let mut opened_preview = match preview {
                        Some((preview_metadata, path)) => Some((
                            preview_metadata,
                            std::fs::File::open(path)
                                .map_err(|e| format!("attachment preview source: {e}"))?,
                        )),
                        None => None,
                    };
                    let preview = opened_preview
                        .as_mut()
                        .map(|(metadata, source)| (&*metadata, source));
                    node.send_view_once_attachment_with_preview(
                        &peer,
                        &metadata,
                        &mut source,
                        preview,
                        lifetime_secs,
                        now,
                        &mut OsRng,
                    )
                    .map_err(fail)
                });
            let _ = resp.send(result);
        }
        Msg::GroupAttachmentSend {
            group,
            metadata,
            path,
            preview,
            resp,
        } => {
            let result = std::fs::File::open(path)
                .map_err(|e| format!("attachment source: {e}"))
                .and_then(|mut source| {
                    let mut opened_preview = match preview {
                        Some((preview_metadata, path)) => Some((
                            preview_metadata,
                            std::fs::File::open(path)
                                .map_err(|e| format!("attachment preview source: {e}"))?,
                        )),
                        None => None,
                    };
                    let preview = opened_preview
                        .as_mut()
                        .map(|(metadata, source)| (&*metadata, source));
                    node.send_group_attachment_with_preview(
                        &group,
                        &metadata,
                        &mut source,
                        preview,
                        now,
                        &mut OsRng,
                    )
                    .map_err(fail)
                });
            let _ = resp.send(result);
        }
        Msg::GroupAttachmentSendViewOnce {
            group,
            metadata,
            path,
            preview,
            lifetime_secs,
            resp,
        } => {
            let result = std::fs::File::open(path)
                .map_err(|e| format!("attachment source: {e}"))
                .and_then(|mut source| {
                    let mut opened_preview = match preview {
                        Some((preview_metadata, path)) => Some((
                            preview_metadata,
                            std::fs::File::open(path)
                                .map_err(|e| format!("attachment preview source: {e}"))?,
                        )),
                        None => None,
                    };
                    let preview = opened_preview
                        .as_mut()
                        .map(|(metadata, source)| (&*metadata, source));
                    node.send_group_view_once_attachment_with_preview(
                        &group,
                        &metadata,
                        &mut source,
                        preview,
                        lifetime_secs,
                        now,
                        &mut OsRng,
                    )
                    .map_err(fail)
                });
            let _ = resp.send(result);
        }
        Msg::Attachments { resp } => {
            let _ = resp.send(node.attachments().map_err(fail));
        }
        Msg::AttachmentAccept { transfer, resp } => {
            let _ = resp.send(
                node.accept_attachment(&transfer, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::AttachmentReject { transfer, resp } => {
            let _ = resp.send(
                node.reject_attachment(&transfer, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::AttachmentCancel { transfer, resp } => {
            let _ = resp.send(
                node.cancel_attachment(&transfer, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::AttachmentPause { transfer, resp } => {
            let _ = resp.send(
                node.pause_attachment(&transfer, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::AttachmentResume { transfer, resp } => {
            let _ = resp.send(
                node.resume_attachment(&transfer, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::AttachmentExport {
            transfer,
            path,
            preview,
            resp,
        } => {
            let result = match open_private(&path) {
                Ok(mut destination) => {
                    let result = node
                        .export_attachment_object(&transfer, preview, &mut destination)
                        .map_err(fail);
                    drop(destination);
                    if result.is_err() {
                        let _ = std::fs::remove_file(&path);
                    }
                    result
                }
                Err(error) => Err(format!("attachment export: {error}")),
            };
            let _ = resp.send(result);
        }
        Msg::AttachmentConsumeViewOnce {
            transfer,
            path,
            resp,
        } => {
            let result = match open_private(&path) {
                Ok(mut destination) => {
                    let result = node
                        .consume_view_once_attachment(&transfer, &mut destination, now, &mut OsRng)
                        .map_err(fail);
                    drop(destination);
                    if result.is_err() {
                        let _ = std::fs::remove_file(&path);
                    }
                    result
                }
                Err(error) => Err(format!("view-once open: {error}")),
            };
            let _ = resp.send(result);
        }
        Msg::Schedule {
            peer,
            body,
            not_before,
            resp,
        } => {
            let _ = resp.send(
                node.schedule_message(&peer, &body, not_before, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::GroupSchedule {
            group,
            body,
            not_before,
            resp,
        } => {
            let _ = resp.send(
                node.schedule_group_message(&group, &body, not_before, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::ScheduledEdit {
            id,
            body,
            not_before,
            resp,
        } => {
            let _ = resp.send(
                node.edit_scheduled_message(&id, &body, not_before, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::ScheduledCancel { id, resp } => {
            let _ = resp.send(node.cancel_scheduled_message(&id).map_err(fail));
        }
        Msg::ScheduledMessages { resp } => {
            let _ = resp.send(node.scheduled_messages().map_err(fail));
        }
        Msg::NoteToSelfSend { body, resp } => {
            let _ = resp.send(node.note_to_self_send(&body, now, &mut OsRng).map_err(fail));
        }
        Msg::NoteToSelfMessages { resp } => {
            let _ = resp.send(node.note_to_self_messages().map_err(fail));
        }
        Msg::Theme { resp } => {
            let result = node.theme_preference().and_then(|preference| {
                node.theme_preference_is_persisted()
                    .map(|persisted| (preference, persisted))
            });
            let _ = resp.send(result.map_err(fail));
        }
        Msg::ThemeSet { preference, resp } => {
            let _ = resp.send(
                node.set_theme_preference(preference, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::CustomIcon { target, resp } => {
            let _ = resp.send(node.custom_icon(&target).map_err(fail));
        }
        Msg::CustomIconSetPath {
            target,
            path,
            crop,
            resp,
        } => {
            let _ = resp.send(
                node.set_custom_icon_from_path(target, &path, crop, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::CustomIconSetBundled {
            target,
            glyph,
            resp,
        } => {
            let _ = resp.send(
                node.set_bundled_custom_icon(target, &glyph, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::CustomIconClear { target, resp } => {
            let _ = resp.send(node.clear_custom_icon(&target).map_err(fail));
        }
        Msg::CustomIconUsage { resp } => {
            let _ = resp.send(node.custom_icon_usage().map_err(fail));
        }
        Msg::FolderCreate { name, resp } => {
            let _ = resp.send(node.create_folder(&name, &mut OsRng).map_err(fail));
        }
        Msg::Folders { resp } => {
            let _ = resp.send(node.folders().map_err(fail));
        }
        Msg::FolderGet { folder, resp } => {
            let _ = resp.send(node.folder(&folder).map_err(fail));
        }
        Msg::FolderRename { folder, name, resp } => {
            let _ = resp.send(node.rename_folder(&folder, &name, &mut OsRng).map_err(fail));
        }
        Msg::FolderReorder { folders, resp } => {
            let _ = resp.send(node.reorder_folders(&folders, &mut OsRng).map_err(fail));
        }
        Msg::FolderDeletePreview { folder, resp } => {
            let _ = resp.send(node.folder_delete_assignment_count(&folder).map_err(fail));
        }
        Msg::FolderDelete { folder, resp } => {
            let _ = resp.send(node.delete_folder(&folder).map_err(fail));
        }
        Msg::FolderMove {
            folder,
            target,
            resp,
        } => {
            let _ = resp.send(
                node.move_conversation_to_folder(&target, &folder, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::FolderUnfile { target, resp } => {
            let _ = resp.send(node.unfile_conversation(&target).map_err(fail));
        }
        Msg::FolderMembership { folder, resp } => {
            let _ = resp.send(node.folder_members(&folder).map_err(fail));
        }
        Msg::ConversationFolder { target, resp } => {
            let _ = resp.send(node.folder_for_conversation(&target).map_err(fail));
        }
        Msg::FolderConversations {
            selection,
            labels,
            mode,
            resp,
        } => {
            let _ = resp.send(
                node.folder_conversations(selection, &labels, mode)
                    .map_err(fail),
            );
        }
        Msg::FolderStale { resp } => {
            let _ = resp.send(node.stale_folder_assignments().map_err(fail));
        }
        Msg::FolderStaleCleanup {
            folder,
            target,
            resp,
        } => {
            let _ = resp.send(
                node.cleanup_stale_folder_assignment(&folder, &target)
                    .map_err(fail),
            );
        }
        Msg::LabelCreate { name, color, resp } => {
            let _ = resp.send(node.create_label(&name, &color, &mut OsRng).map_err(fail));
        }
        Msg::Labels { resp } => {
            let _ = resp.send(node.labels().map_err(fail));
        }
        Msg::LabelGet { label, resp } => {
            let _ = resp.send(node.label(&label).map_err(fail));
        }
        Msg::LabelUpdate {
            label,
            name,
            color,
            resp,
        } => {
            let _ = resp.send(
                node.update_label(&label, &name, &color, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::LabelDeletePreview { label, resp } => {
            let _ = resp.send(node.label_delete_assignment_count(&label).map_err(fail));
        }
        Msg::LabelDelete { label, resp } => {
            let _ = resp.send(node.delete_label(&label).map_err(fail));
        }
        Msg::LabelAssign {
            label,
            target,
            resp,
        } => {
            let _ = resp.send(node.assign_label(&label, &target, &mut OsRng).map_err(fail));
        }
        Msg::LabelUnassign {
            label,
            target,
            resp,
        } => {
            let _ = resp.send(node.unassign_label(&label, &target).map_err(fail));
        }
        Msg::LabelMembership { label, resp } => {
            let _ = resp.send(node.label_members(&label).map_err(fail));
        }
        Msg::LabelsForConversation { target, resp } => {
            let _ = resp.send(node.labels_for_conversation(&target).map_err(fail));
        }
        Msg::LabelStale { resp } => {
            let _ = resp.send(node.stale_label_assignments().map_err(fail));
        }
        Msg::LabelStaleCleanup {
            label,
            target,
            resp,
        } => {
            let _ = resp.send(
                node.cleanup_stale_label_assignment(&label, &target)
                    .map_err(fail),
            );
        }
        Msg::LabelFilter { labels, mode, resp } => {
            let _ = resp.send(node.filter_label_conversations(&labels, mode).map_err(fail));
        }
        Msg::Pin { target, resp } => {
            let _ = resp.send(node.pin_conversation(&target, &mut OsRng).map_err(fail));
        }
        Msg::Unpin { target, resp } => {
            let _ = resp.send(node.unpin_conversation(&target).map_err(fail));
        }
        Msg::PinState { target, resp } => {
            let _ = resp.send(node.pin_state(&target).map_err(fail));
        }
        Msg::Pins { resp } => {
            let _ = resp.send(node.pins().map_err(fail));
        }
        Msg::PinReorder { targets, resp } => {
            let _ = resp.send(node.reorder_pins(&targets, &mut OsRng).map_err(fail));
        }
        Msg::PinStale { resp } => {
            let _ = resp.send(node.stale_pins().map_err(fail));
        }
        Msg::PinStaleCleanup { target, resp } => {
            let _ = resp.send(node.cleanup_stale_pin(&target).map_err(fail));
        }
        Msg::PinConversations {
            selection,
            labels,
            mode,
            resp,
        } => {
            let _ = resp.send(
                node.pin_conversations(selection, &labels, mode)
                    .map_err(fail),
            );
        }
        Msg::GroupCreate {
            name,
            members,
            resp,
        } => {
            let _ = resp.send(node.create_group(&name, &members, &mut OsRng).map_err(fail));
        }
        Msg::GroupSecurity { group, resp } => {
            let _ = resp.send(node.group_security_info(&group).map_err(fail));
        }
        Msg::GroupUpgradeSecurity { group, resp } => {
            let _ = resp.send(
                node.group_upgrade_security(&group, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::GroupSend { group, body, resp } => {
            let _ = resp.send(
                node.group_send(&group, &body, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::GroupSendDisappearing {
            group,
            body,
            lifetime_secs,
            resp,
        } => {
            let _ = resp.send(
                node.group_send_disappearing_message(&group, &body, lifetime_secs, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::GroupEditMessage {
            group,
            target_author,
            target_content_id,
            text,
            resp,
        } => {
            let _ = resp.send(
                node.group_edit_message(
                    &group,
                    target_author,
                    target_content_id,
                    &text,
                    now,
                    &mut OsRng,
                )
                .map_err(fail),
            );
        }
        Msg::GroupMentionCapability { group, resp } => {
            let _ = resp.send(node.group_mention_capability(&group).map_err(fail));
        }
        Msg::GroupMentionSend {
            group,
            text,
            spans,
            review_token,
            resp,
        } => {
            let _ = resp.send(
                node.group_send_mention(&group, &text, &spans, review_token, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::GroupPollCreate {
            group,
            question,
            options,
            resp,
        } => {
            let _ = resp.send(
                node.group_create_poll(&group, &question, &options, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::GroupPolls { group, resp } => {
            let _ = resp.send(node.group_polls(&group).map_err(fail));
        }
        Msg::GroupPollVote {
            group,
            poll_author,
            poll_id,
            option_id,
            resp,
        } => {
            let _ = resp.send(
                node.group_vote_poll(&group, poll_author, poll_id, option_id, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::GroupPollClose {
            group,
            poll_author,
            poll_id,
            resp,
        } => {
            let _ = resp.send(
                node.group_close_poll(&group, poll_author, poll_id, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::GroupPollModerateClose {
            group,
            poll_author,
            poll_id,
            resp,
        } => {
            let _ = resp.send(
                node.group_moderate_poll_close(&group, poll_author, poll_id, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::GroupAuthority { group, resp } => {
            let _ = resp.send(node.group_authority(&group).map_err(fail));
        }
        Msg::GroupUpgradeAuthority { group, resp } => {
            let _ = resp.send(
                node.group_upgrade_authority(&group, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::GroupRename { group, name, resp } => {
            let _ = resp.send(
                node.group_rename(&group, &name, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::GroupSetRole {
            group,
            peer,
            role,
            resp,
        } => {
            let _ = resp.send(
                node.group_set_role(&group, peer, role, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::GroupTransferOwner { group, peer, resp } => {
            let _ = resp.send(
                node.group_transfer_owner(&group, peer, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::GroupAdd { group, peer, resp } => {
            let _ = resp.send(node.group_add(&group, &peer, now, &mut OsRng).map_err(fail));
        }
        Msg::GroupRemove { group, peer, resp } => {
            let _ = resp.send(
                node.group_remove(&group, &peer, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::GroupLeave { group, resp } => {
            let _ = resp.send(node.group_leave(&group, now, &mut OsRng).map_err(fail));
        }
        Msg::GroupInvitations { resp } => {
            let _ = resp.send(node.group_invitations().map_err(fail));
        }
        Msg::GroupInvitationAccept { invitation, resp } => {
            let _ = resp.send(
                node.accept_group_invitation(&invitation, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::GroupInvitationDelete { invitation, resp } => {
            let _ = resp.send(
                node.delete_group_invitation(&invitation, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::Groups { resp } => {
            let _ = resp.send(node.groups().map_err(fail));
        }
        Msg::GroupMessages { group, resp } => {
            let _ = resp.send(node.resolved_group_messages(&group).map_err(fail));
        }
        Msg::Contacts { resp } => {
            let _ = resp.send(node.contacts().map_err(fail));
        }
        Msg::MessageRequests { resp } => {
            let _ = resp.send(node.message_requests().map_err(fail));
        }
        Msg::MessageRequestAccept {
            request,
            name,
            resp,
        } => {
            let _ = resp.send(
                node.accept_message_request(&request, &name, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::MessageRequestDelete { request, resp } => {
            let _ = resp.send(
                node.delete_message_request(&request, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::MessageRequestBlock { request, resp } => {
            let _ = resp.send(
                node.block_message_request(&request, now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::CarrierCapabilities { resp } => {
            let _ = resp.send(node.carrier_capabilities(now).map_err(fail));
        }
        Msg::Calls { resp } => {
            let _ = resp.send(Ok(node.calls()));
        }
        Msg::CallAvailability { peer, resp } => {
            let _ = resp.send(node.call_availability(&peer, now).map_err(fail));
        }
        Msg::CallStart { peer, resp } => {
            let _ = resp.send(node.start_call(&peer, now, &mut OsRng).map_err(fail));
        }
        Msg::CallAnswer { call, resp } => {
            let _ = resp.send(node.answer_call(&call, now, &mut OsRng).map_err(fail));
        }
        Msg::CallDecline { call, resp } => {
            let _ = resp.send(node.decline_call(&call, now, &mut OsRng).map_err(fail));
        }
        Msg::CallCancel { call, resp } => {
            let _ = resp.send(node.cancel_call(&call, now, &mut OsRng).map_err(fail));
        }
        Msg::CallHangup { call, resp } => {
            let _ = resp.send(node.hangup_call(&call, now, &mut OsRng).map_err(fail));
        }
        Msg::CallAudioSend {
            call,
            timestamp_ms,
            mut opus_packet,
            resp,
        } => {
            let result = node
                .send_call_audio(&call, timestamp_ms, &opus_packet)
                .map_err(fail);
            opus_packet.fill(0);
            let _ = resp.send(result);
        }
        Msg::CallAudioTake { call, resp } => {
            let _ = resp.send(node.take_call_audio(&call).map_err(fail));
        }
        Msg::Messages { peer, resp } => {
            let _ = resp.send(node.resolved_messages_with(&peer).map_err(fail));
        }
        Msg::SafetyNumber { peer, resp } => {
            let _ = resp.send(node.safety_number_with(&peer).map_err(fail));
        }
        Msg::MarkVerified { peer, resp } => {
            let _ = resp.send(node.mark_verified(&peer, &mut OsRng).map_err(fail));
        }
        Msg::SetHints { peer, hints, resp } => {
            let _ = resp.send(node.set_hints(&peer, &hints, &mut OsRng).map_err(fail));
        }
        Msg::RendezvousRefresh { peer, resp } => {
            let _ = resp.send(node.request_rendezvous_refresh(&peer).map_err(fail));
        }
        Msg::RendezvousConversationActive { peer, active, resp } => {
            let _ = resp.send(
                node.set_rendezvous_conversation_active(&peer, active)
                    .map_err(fail),
            );
        }
        Msg::Publish { resp } => {
            let hints = own_hints(net, &cfg.mailboxes);
            let _ = resp.send(
                node.publish_bundle_with_policy(&hints, cfg.discovery_policy, now)
                    .await
                    .map_err(fail),
            );
        }
        Msg::Backup { path, resp } => {
            let result = node
                .export_backup(now, &mut OsRng)
                .map_err(|e| e.to_string())
                .and_then(|(file, mnemonic)| {
                    write_private(&path, &file)
                        .map(|()| (*mnemonic).clone())
                        .map_err(|e| format!("backup write: {e}"))
                });
            let _ = resp.send(result);
        }
        Msg::RecoveryAuthorityExport { path, resp } => {
            let result = node
                .export_account_recovery_authority(&path)
                .map(|mnemonic| (*mnemonic).clone())
                .map_err(fail);
            let _ = resp.send(result);
        }
        Msg::RefreshHandshakeBundle { cache } => {
            let hints = own_hints(net, &cfg.mailboxes);
            let bundle = node.handshake_bundle_with_hints(&hints, now, &mut OsRng);
            let mut cache = cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Ok(bundle) = bundle {
                cache.current = bundle;
            }
            cache.refresh_pending = false;
        }
        Msg::Tokens { resp } => {
            let _ = resp.send(node.mailbox_tokens(now));
        }
        Msg::WakeCollect { budget_ms, resp } => {
            let started = Instant::now();
            let budget = Duration::from_millis(u64::from(budget_ms))
                .min(kult_node::MAX_WAKE_COLLECTION_DURATION);
            let tokens = node.mailbox_tokens(now);
            for mailbox in cfg.mailboxes.iter().take(MAX_MAILBOXES_PER_CHECKIN_TICK) {
                let remaining = budget.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    break;
                }
                let _ = tokio::time::timeout(
                    remaining,
                    net.mailbox_checkin(
                        mailbox,
                        &tokens[..tokens.len().min(MAX_MAILBOX_CHECKIN_TOKENS)],
                    ),
                )
                .await;
            }
            let remaining = budget.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                let _ = resp.send(Ok(0));
            } else {
                let result = node
                    .wake_tick(now, remaining, &mut OsRng)
                    .await
                    .map_err(fail)
                    .map(|batch| {
                        let count = u32::try_from(batch.len()).unwrap_or(u32::MAX);
                        for event in batch {
                            let _ = events.send(event);
                        }
                        count
                    });
                let _ = resp.send(result);
            }
        }
        Msg::WakeRegister {
            platform,
            environment,
            profile,
            mut provider_token,
            app_topic,
            resp,
        } => {
            let result = node
                .register_native_wake_destination(
                    NativeWakeDestinationRegistration {
                        platform,
                        environment,
                        profile,
                        provider_token: &provider_token,
                        app_topic: &app_topic,
                        providers: &cfg.wake,
                        now,
                    },
                    &mut OsRng,
                )
                .await
                .map_err(fail);
            provider_token.fill(0);
            let _ = resp.send(result);
        }
        Msg::WakeRevoke { resp } => {
            let _ = resp.send(
                node.revoke_native_wake_capabilities(now, &mut OsRng)
                    .map_err(fail),
            );
        }
        Msg::BridgeRelays(relays) => node.set_bridge(Some(relays)),
    }
}

/// Ask the actor to publish the prekey bundle, ignoring the outcome — the
/// lifecycle retries on its own schedule.
async fn publish_quiet(tx: &mpsc::Sender<Msg>) {
    let (resp, _rx) = oneshot::channel();
    let _ = tx.send(Msg::Publish { resp }).await;
}

/// Background lifecycle: bootstrap, publish, NAT probing + relay
/// reservation, mailbox check-ins. Everything here is best-effort and
/// retried on its interval — the node works without connectivity and picks
/// these up when it appears. Kept in lockstep with `kultd`'s lifecycle.
async fn lifecycle(
    cfg: RuntimeConfig,
    net: Arc<Libp2pTransport>,
    tx: mpsc::Sender<Msg>,
    mut shutdown: watch::Receiver<bool>,
) {
    if net.wait_listen_addr().await.is_err() {
        eprintln!("kult-ffi: no listen address bound");
    }
    let bridging = cfg.bridge && (cfg.meshtastic_serial.is_some() || cfg.meshtastic_tcp.is_some());
    if bridging && cfg.serve_mailbox {
        // Now that an address is bound, mesh-heard transit can also be
        // deposited into this node's own mailbox service (resolved locally
        // by the transport — no self-dial).
        if let Some(addr) = net.listen_addrs().into_iter().next() {
            let relays = bridge_relays(&cfg, Some(&addr));
            let _ = tx.send(Msg::BridgeRelays(relays)).await;
        }
    }
    if !cfg.bootstrap.is_empty() {
        let peers: Vec<&str> = cfg.bootstrap.iter().map(String::as_str).collect();
        if let Err(e) = net.bootstrap(&peers).await {
            eprintln!("kult-ffi: DHT bootstrap failed: {e}");
        }
        // Publish once the DHT has peers (a lone node has nowhere to put
        // records; contacts then come from out-of-band bundles instead).
        publish_quiet(&tx).await;
    }

    let relay_candidate = cfg.relay.clone().or_else(|| cfg.bootstrap.first().cloned());
    let mut circuit_reserved = false;
    let mut nat_tick = tokio::time::interval(cfg.nat_interval);
    let mut checkin_tick = tokio::time::interval(cfg.checkin_interval);
    // Bootstrap-less LAN operation has no publish trigger above, yet peers
    // resolving this node's current (OS-assigned, per-run) ports depend on
    // the republished bundle. Republish whenever mDNS shows a new LAN peer:
    // the routing table just gained somewhere to put the record, and that
    // peer may hold a queued message stuck on this node's previous address.
    let mut lan_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut lan_tick = tokio::time::interval(std::time::Duration::from_secs(15));
    let mut mailbox_cursor = 0usize;
    let mut mailbox_token_cursors: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut mailbox_retry: std::collections::HashMap<String, MailboxRetry> =
        std::collections::HashMap::new();
    let mut jitter_rng = OsRng;
    let discovery_day = Duration::from_secs(24 * 60 * 60);
    let discovery_offset = Duration::from_secs(jitter_rng.next_u64() % discovery_day.as_secs());
    let mut discovery_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + discovery_offset,
        discovery_day,
    );
    discovery_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = discovery_tick.tick() => {
                publish_quiet(&tx).await;
            }
            _ = lan_tick.tick() => {
                let peers: std::collections::HashSet<String> =
                    net.lan_peers().into_iter().collect();
                if peers.difference(&lan_seen).next().is_some() {
                    publish_quiet(&tx).await;
                }
                lan_seen = peers;
            }
            _ = nat_tick.tick() => {
                if circuit_reserved {
                    continue;
                }
                let Some(relay) = &relay_candidate else { continue };
                if let Ok(kult_transport::NatStatus::Private) = net.nat_status().await {
                    match net.reserve_relay(relay).await {
                        Ok(_) => {
                            circuit_reserved = true;
                            // The circuit is a new listen address — republish.
                            publish_quiet(&tx).await;
                        }
                        Err(e) => eprintln!("kult-ffi: relay reservation failed: {e}"),
                    }
                }
            }
            _ = checkin_tick.tick() => {
                if cfg.mailboxes.is_empty() {
                    continue;
                }
                let (resp, rx) = oneshot::channel();
                if tx.send(Msg::Tokens { resp }).await.is_err() {
                    break;
                }
                let Ok(tokens) = rx.await else { break };
                let mailboxes = rotating_batch(
                    &cfg.mailboxes,
                    &mut mailbox_cursor,
                    MAX_MAILBOXES_PER_CHECKIN_TICK,
                );
                for mailbox in mailboxes {
                    if mailbox_retry
                        .get(&mailbox)
                        .is_some_and(|retry| retry.next_at > Instant::now())
                    {
                        continue;
                    }
                    let token_cursor = mailbox_token_cursors
                        .entry(mailbox.clone())
                        .or_default();
                    let token_batch =
                        rotating_batch(&tokens, token_cursor, MAX_MAILBOX_CHECKIN_TOKENS);
                    let result = net.mailbox_checkin(&mailbox, &token_batch).await;
                    let retry = mailbox_retry.entry(mailbox.clone()).or_insert(MailboxRetry {
                        failures: 0,
                        next_at: Instant::now(),
                    });
                    match result {
                        Ok(_) => {
                            retry.failures = 0;
                            retry.next_at = Instant::now()
                                + jittered_mailbox_delay(
                                    cfg.checkin_interval,
                                    0,
                                    jitter_rng.next_u64(),
                                );
                        }
                        Err(_) => {
                            retry.failures = retry.failures.saturating_add(1);
                            retry.next_at = Instant::now()
                                + jittered_mailbox_delay(
                                    cfg.checkin_interval,
                                    retry.failures,
                                    jitter_rng.next_u64(),
                                );
                        }
                    }
                }
            }
        }
    }
}
