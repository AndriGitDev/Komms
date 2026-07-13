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
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(e) => write!(f, "store error: {e}"),
            Self::Crypto(e) => write!(f, "crypto error: {e}"),
            Self::Protocol(e) => write!(f, "protocol error: {e}"),
            Self::Transport(e) => write!(f, "transport error: {e}"),
            Self::UnknownPeer => f.write_str("peer is not a stored contact"),
            Self::NoSession => f.write_str("no session and no prekey bundle for this peer"),
            Self::CorruptState => f.write_str("node state missing or corrupt"),
            Self::NoDiscovery => f.write_str("no usable discovery plane"),
            Self::BundleNotFound => f.write_str("no verifiable prekey bundle found for address"),
            Self::UnknownGroup => f.write_str("group id names no stored group"),
            Self::NotGroupCreator => f.write_str("only the group creator may change it"),
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
