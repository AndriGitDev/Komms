//! Node-level failures. Honest by design: nothing here is ever downgraded
//! to a fake success (docs/09-implementation-guide.md ground rule 4).

/// Failures surfaced by the node runtime.
#[derive(Debug)]
#[non_exhaustive]
pub enum NodeError {
    /// Storage failure.
    Store(kult_store::StoreError),
    /// Cryptographic failure.
    Crypto(kult_crypto::CryptoError),
    /// Protocol-level failure.
    Protocol(kult_protocol::ProtocolError),
    /// Transport failure.
    Transport(kult_transport::TransportError),
    /// The peer is not a stored contact.
    UnknownPeer,
    /// The bounded message-request id is absent or has expired.
    UnknownMessageRequest,
    /// The bounded group-invitation id is absent, invalid, or has expired.
    UnknownGroupInvitation,
    /// A local petname is empty, control-bearing, or exceeds its canonical bound.
    InvalidContactName,
    /// The proposed petname has warnings that the caller has not acknowledged.
    ContactNameReviewRequired,
    /// A copied-root reset preserved this petname, but the new account safety
    /// number has not yet been compared out of band.
    ContactReverificationRequired,
    /// Local text-formatting source or highlight ranges violate shared bounds.
    InvalidTextFormatting,
    /// No established session and no stored prekey bundle to start one —
    /// this contact was learned from an inbound handshake that hasn't
    /// completed, or their bundle was never imported.
    NoSession,
    /// The store exists but was never initialized as a node (no identity or
    /// prekeys) — or a stored runtime record failed to parse.
    CorruptState,
    /// No discovery plane is registered, or none of the registered ones
    /// accepted the operation.
    NoDiscovery,
    /// Discovery returned no prekey bundle that verifies *and* matches the
    /// requested address — an unpublished peer and a forged record are
    /// deliberately indistinguishable here.
    BundleNotFound,
    /// Optional post-pairing rendezvous is disabled, invalidly configured, or
    /// lacks the authenticated session material required for this operation.
    RendezvousUnavailable,
    /// The same authenticated rendezvous generation described two different
    /// complete provider sets or route records.
    RendezvousConflict,
    /// The group id names no stored group.
    UnknownGroup,
    /// Only the group's creator may add, remove, or re-key (ADR-0012).
    NotGroupCreator,
    /// This group still has membership-authenticated sender-key state or an
    /// active device that has not authenticated ADR-0029 support.
    GroupSecurityUpgradeRequired,
    /// Mention targets or UTF-8 byte ranges are invalid for the current group.
    InvalidMention,
    /// One or more current co-members do not support exact Mention content.
    MentionUnsupported,
    /// Roster, local display mapping, or authenticated capability state changed
    /// since the user reviewed the composer.
    MentionReviewRequired,
    /// The peer or one current group member has not authenticated Edit v1 support.
    EditUnsupported,
    /// The edit target, author, content kind, revision, or text is invalid.
    InvalidEdit,
    /// The target already has the maximum number of locally authored edits.
    EditLimit,
    /// One or more current co-members lack authenticated Poll v1 support.
    PollUnsupported,
    /// Poll shape, target, option, electorate, author, or transition is invalid.
    InvalidPoll,
    /// This identity has exhausted the bounded local vote-revision budget.
    PollVoteLimit,
    /// A creator-authored final snapshot has already closed this poll.
    PollClosed,
    /// Only the authenticated creator of this exact poll may close it.
    NotPollCreator,
    /// Call control, target, route, expiry, or transition is invalid.
    InvalidCall,
    /// No transient call with this id exists on this installation.
    UnknownCall,
    /// The peer does not advertise the canonical call-control contract.
    CallUnsupported,
    /// No fresh direct QUIC carrier is available for this call.
    CallUnavailable,
    /// This installation already has a non-terminal call.
    CallBusy,
    /// Signed group-authority content or transition is malformed or misplaced.
    InvalidGroupAuthority,
    /// One or more current members lack signed C6 role support.
    GroupRolesUnsupported,
    /// The operation requires the current group owner.
    NotGroupOwner,
    /// Role assignment or target violates the fixed C6 role table.
    InvalidGroupRole,
    /// The sole owner must transfer ownership before leaving/removal.
    LastGroupOwner,
    /// The peer/group lacks ephemeral v1 plus envelope-v2 support.
    EphemeralUnsupported,
    /// Lifetime, deadline, content, hint binding, or lifecycle is invalid.
    InvalidEphemeral,
    /// Ordinary preview/export is forbidden for a view-once attachment.
    ViewOnceExportForbidden,
    /// The peer has not authenticated support for the complete attachment
    /// manifest and bulk-lane contract.
    AttachmentUnsupported,
    /// A local attachment transfer id does not exist or is quarantined.
    UnknownAttachment,
    /// Attachment input or a requested lifecycle transition is invalid.
    InvalidAttachment,
    /// A custom-icon source, crop, glyph, or canonical encoded record is invalid.
    InvalidCustomIcon,
    /// A custom-icon target is not a current local contact, group, or folder.
    UnavailableCustomIconTarget,
    /// Reading the caller-selected custom-icon source failed.
    CustomIconIo(std::io::Error),
    /// A scheduled message id no longer exists (it was cancelled or activated).
    UnknownScheduledMessage,
    /// The requested schedule is in the past or its body is invalid.
    InvalidSchedule,
    /// Streaming import or export failed.
    MediaIo(std::io::Error),
    /// A link ceremony payload, state transition, or confirmation is invalid.
    InvalidDeviceLink,
    /// Linking would replace non-empty state on the proposed target device.
    DeviceLinkTargetNotEmpty,
    /// No matching source/target ceremony is currently pending in memory.
    NoPendingDeviceLink,
    /// No ordinary device-authority proposal is awaiting additional approval.
    NoPendingDeviceAuthority,
    /// An ordinary device-authority approval or proposal is malformed,
    /// mismatched, or belongs to a different operation.
    InvalidDeviceAuthority,
    /// The exact physical-device id is unknown or already revoked.
    UnknownLinkedDevice,
    /// The current physical installation cannot revoke itself in place.
    CannotRevokeCurrentDevice,
    /// A device-sync bundle was replayed, rolled back, or addressed elsewhere.
    InvalidDeviceSync,
    /// A contact device manifest is stale, fork-losing, or rewrites authority.
    InvalidDeviceManifest,
    /// A pre-ADR-0026 single-device profile requires explicit recovery export.
    AuthorityMigrationRequired,
    /// A copied-root Alpha profile requires a visible new-identity reset.
    AuthorityResetRequired,
    /// A root-free backup needs the separately held offline recovery package
    /// and its mnemonic before stable identity recovery can proceed.
    RecoveryAuthorityRequired,
    /// Too many failed local attempts opened the same offline authority.
    RecoveryAttemptLimited,
    /// The one-time genesis recovery authority was already exported or this
    /// profile was opened from an existing store.
    RecoveryAuthorityUnavailable,
    /// The proposed transition still lacks a strict majority of active devices.
    DeviceQuorumRequired,
    /// A concurrent valid ordinary authority branch was observed.
    DeviceAuthorityFork,
    /// Different root transitions claim the same recovery epoch.
    DeviceRecoveryConflict,
    /// Authority state descends from an already superseded recovery epoch.
    OldDeviceAuthorityEpoch,
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "store error: {e}"),
            Self::Crypto(e) => write!(f, "crypto error: {e}"),
            Self::Protocol(e) => write!(f, "protocol error: {e}"),
            Self::Transport(e) => write!(f, "transport error: {e}"),
            Self::UnknownPeer => f.write_str("peer is not a stored contact"),
            Self::UnknownMessageRequest => {
                f.write_str("message request does not exist or has expired")
            }
            Self::UnknownGroupInvitation => {
                f.write_str("group invitation does not exist or has expired")
            }
            Self::InvalidContactName => f.write_str("invalid contact name"),
            Self::ContactNameReviewRequired => {
                f.write_str("contact name warnings require explicit confirmation")
            }
            Self::ContactReverificationRequired => {
                f.write_str("contact requires safety-number re-verification after authority reset")
            }
            Self::InvalidTextFormatting => f.write_str("invalid text formatting request"),
            Self::NoSession => f.write_str("no session and no prekey bundle for this peer"),
            Self::CorruptState => f.write_str("node state missing or corrupt"),
            Self::NoDiscovery => f.write_str("no usable discovery plane"),
            Self::BundleNotFound => f.write_str("no verifiable prekey bundle found for address"),
            Self::RendezvousUnavailable => {
                f.write_str("pairwise rendezvous is unavailable for this relationship")
            }
            Self::RendezvousConflict => {
                f.write_str("conflicting pairwise rendezvous state was detected")
            }
            Self::UnknownGroup => f.write_str("group id names no stored group"),
            Self::NotGroupCreator => f.write_str("only the group creator may change it"),
            Self::GroupSecurityUpgradeRequired => {
                f.write_str("group security upgrade is required before this action")
            }
            Self::InvalidMention => f.write_str("invalid group mention text, range, or target"),
            Self::MentionUnsupported => {
                f.write_str("one or more group members do not support mentions")
            }
            Self::MentionReviewRequired => {
                f.write_str("group mention state changed; review is required again")
            }
            Self::EditUnsupported => {
                f.write_str("peer or group member does not support message edits")
            }
            Self::InvalidEdit => f.write_str("invalid message edit target, author, or text"),
            Self::EditLimit => f.write_str("message edit limit reached"),
            Self::PollUnsupported => f.write_str("one or more group members do not support polls"),
            Self::InvalidPoll => f.write_str("invalid group poll, option, voter, or target"),
            Self::PollVoteLimit => f.write_str("poll vote revision limit reached"),
            Self::PollClosed => f.write_str("poll is already closed"),
            Self::NotPollCreator => f.write_str("only the poll creator may close it"),
            Self::InvalidCall => f.write_str("invalid call control, route, expiry, or transition"),
            Self::UnknownCall => f.write_str("call does not exist on this installation"),
            Self::CallUnsupported => f.write_str("peer does not support live calls"),
            Self::CallUnavailable => f.write_str("no fresh direct QUIC route is available"),
            Self::CallBusy => f.write_str("this installation is already in a call"),
            Self::InvalidGroupAuthority => f.write_str("invalid group authority transition"),
            Self::GroupRolesUnsupported => {
                f.write_str("one or more group members do not support signed roles")
            }
            Self::NotGroupOwner => f.write_str("only the current group owner may do that"),
            Self::InvalidGroupRole => f.write_str("invalid group role or role target"),
            Self::LastGroupOwner => f.write_str("transfer ownership before the owner can leave"),
            Self::EphemeralUnsupported => {
                f.write_str("peer or group member does not support ephemeral content")
            }
            Self::InvalidEphemeral => f.write_str("invalid ephemeral content or lifecycle"),
            Self::ViewOnceExportForbidden => {
                f.write_str("view-once attachment requires terminal consume")
            }
            Self::AttachmentUnsupported => {
                f.write_str("peer does not advertise attachment support")
            }
            Self::UnknownAttachment => f.write_str("attachment transfer does not exist"),
            Self::InvalidAttachment => f.write_str("invalid attachment state or metadata"),
            Self::InvalidCustomIcon => f.write_str("invalid custom icon source, crop, or glyph"),
            Self::UnavailableCustomIconTarget => f.write_str("custom icon target is unavailable"),
            Self::CustomIconIo(e) => write!(f, "custom icon input error: {e}"),
            Self::UnknownScheduledMessage => {
                f.write_str("scheduled message does not exist or already activated")
            }
            Self::InvalidSchedule => f.write_str("invalid scheduled message or send instant"),
            Self::MediaIo(e) => write!(f, "attachment stream error: {e}"),
            Self::InvalidDeviceLink => f.write_str("invalid or unconfirmed device link"),
            Self::DeviceLinkTargetNotEmpty => {
                f.write_str("device linking target contains existing account state")
            }
            Self::NoPendingDeviceLink => f.write_str("no matching device link is pending"),
            Self::NoPendingDeviceAuthority => {
                f.write_str("no device authority proposal is pending")
            }
            Self::InvalidDeviceAuthority => {
                f.write_str("invalid or mismatched device authority proposal")
            }
            Self::UnknownLinkedDevice => f.write_str("linked device is unknown or revoked"),
            Self::CannotRevokeCurrentDevice => {
                f.write_str("the current device cannot revoke itself")
            }
            Self::InvalidDeviceSync => f.write_str("invalid or replayed device sync bundle"),
            Self::InvalidDeviceManifest => {
                f.write_str("invalid or rolled-back contact device manifest")
            }
            Self::AuthorityMigrationRequired => {
                f.write_str("explicit offline-authority migration is required")
            }
            Self::AuthorityResetRequired => {
                f.write_str("an authority reset with a new identity is required")
            }
            Self::RecoveryAuthorityRequired => {
                f.write_str("the offline account recovery authority is required")
            }
            Self::RecoveryAttemptLimited => f.write_str(
                "offline recovery attempts are temporarily limited; wait before retrying",
            ),
            Self::RecoveryAuthorityUnavailable => {
                f.write_str("no unexported offline account recovery authority is available")
            }
            Self::DeviceQuorumRequired => {
                f.write_str("additional active-device approval is required")
            }
            Self::DeviceAuthorityFork => {
                f.write_str("a conflicting device-authority branch was detected")
            }
            Self::DeviceRecoveryConflict => {
                f.write_str("conflicting account-root recoveries were detected")
            }
            Self::OldDeviceAuthorityEpoch => {
                f.write_str("device authority belongs to an older recovery epoch")
            }
        }
    }
}

impl std::error::Error for NodeError {}

impl From<kult_store::StoreError> for NodeError {
    fn from(e: kult_store::StoreError) -> Self {
        Self::Store(e)
    }
}
impl From<kult_crypto::CryptoError> for NodeError {
    fn from(e: kult_crypto::CryptoError) -> Self {
        Self::Crypto(e)
    }
}
impl From<kult_protocol::ProtocolError> for NodeError {
    fn from(e: kult_protocol::ProtocolError) -> Self {
        Self::Protocol(e)
    }
}
impl From<kult_transport::TransportError> for NodeError {
    fn from(e: kult_transport::TransportError) -> Self {
        Self::Transport(e)
    }
}
impl From<std::io::Error> for NodeError {
    fn from(e: std::io::Error) -> Self {
        Self::MediaIo(e)
    }
}
