//! Error type for the protocol layer.

use core::fmt;

/// Failures surfaced by `kult-protocol`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtocolError {
    /// Wire bytes could not be parsed (bad magic, length, version, or kind).
    Malformed,
    /// Payload exceeds the largest padding bucket; chunk it first.
    TooLarge,
    /// Padding was structurally invalid on removal.
    BadPadding,
    /// MTU too small to carry a fragment header plus at least one byte.
    MtuTooSmall,
    /// Message would need more fragments than the format can index.
    TooManyFragments,
    /// Reassembly bounds exceeded (partial cap or per-message size cap).
    ReassemblyOverflow,
    /// Completed reassembly failed its integrity check.
    IntegrityMismatch,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Malformed => "malformed protocol bytes",
            Self::TooLarge => "payload exceeds largest padding bucket",
            Self::BadPadding => "invalid padding",
            Self::MtuTooSmall => "mtu too small for fragmentation",
            Self::TooManyFragments => "fragment count exceeds format limit",
            Self::ReassemblyOverflow => "reassembly bounds exceeded",
            Self::IntegrityMismatch => "reassembled message failed integrity check",
        };
        f.write_str(s)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ProtocolError {}
