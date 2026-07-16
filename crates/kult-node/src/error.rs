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
    /// A local petname is empty, control-bearing, or exceeds its canonical bound.
    InvalidContactName,
    /// The proposed petname has warnings that the caller has not acknowledged.
    ContactNameReviewRequired,
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
    /// The group id names no stored group.
    UnknownGroup,
    /// Only the group's creator may add, remove, or re-key (ADR-0012).
    NotGroupCreator,
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
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "store error: {e}"),
            Self::Crypto(e) => write!(f, "crypto error: {e}"),
            Self::Protocol(e) => write!(f, "protocol error: {e}"),
            Self::Transport(e) => write!(f, "transport error: {e}"),
            Self::UnknownPeer => f.write_str("peer is not a stored contact"),
            Self::InvalidContactName => f.write_str("invalid contact name"),
            Self::ContactNameReviewRequired => {
                f.write_str("contact name warnings require explicit confirmation")
            }
            Self::InvalidTextFormatting => f.write_str("invalid text formatting request"),
            Self::NoSession => f.write_str("no session and no prekey bundle for this peer"),
            Self::CorruptState => f.write_str("node state missing or corrupt"),
            Self::NoDiscovery => f.write_str("no usable discovery plane"),
            Self::BundleNotFound => f.write_str("no verifiable prekey bundle found for address"),
            Self::UnknownGroup => f.write_str("group id names no stored group"),
            Self::NotGroupCreator => f.write_str("only the group creator may change it"),
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
