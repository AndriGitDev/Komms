//! Error type for the crypto core.

use core::fmt;

/// Failures surfaced by `kult-crypto`.
///
/// Variants are deliberately coarse: distinguishing *why* an AEAD failed
/// would create a decryption oracle. No variant ever carries key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// A signature did not verify (prekey bundle, cross-sign, transition).
    InvalidSignature,
    /// A prekey bundle is malformed, expired, or internally inconsistent.
    InvalidBundle,
    /// A wire message could not be parsed or has an unsupported version.
    InvalidMessage,
    /// No known header key decrypts the message header.
    HeaderAuthentication,
    /// The payload AEAD failed to authenticate.
    MessageAuthentication,
    /// Accepting this message would exceed the skipped-message-key bounds
    /// (`MAX_SKIP`); fail closed per spec §4.
    TooManySkipped,
    /// Key material had the wrong length or encoding.
    InvalidKey,
    /// A kult address string failed to parse (prefix, base32, or multihash).
    InvalidAddress,
    /// Handshake inputs are inconsistent (e.g. prekey ids do not match).
    HandshakeMismatch,
    /// (De)serialization of state or messages failed.
    Serialization,
    /// The Argon2id parameters were rejected.
    KdfParams,
    /// A mnemonic phrase is malformed: wrong word count, unknown word, or
    /// failing checksum. Deliberately not more specific — a typo and a
    /// wrong phrase look the same.
    InvalidMnemonic,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::InvalidSignature => "signature verification failed",
            Self::InvalidBundle => "invalid or expired prekey bundle",
            Self::InvalidMessage => "malformed or unsupported message",
            Self::HeaderAuthentication => "header authentication failed",
            Self::MessageAuthentication => "message authentication failed",
            Self::TooManySkipped => "skipped-message bound exceeded",
            Self::InvalidKey => "invalid key material",
            Self::InvalidAddress => "malformed kult address",
            Self::HandshakeMismatch => "handshake inputs inconsistent",
            Self::Serialization => "serialization failure",
            Self::KdfParams => "invalid KDF parameters",
            Self::InvalidMnemonic => "invalid mnemonic phrase",
        };
        f.write_str(s)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}
