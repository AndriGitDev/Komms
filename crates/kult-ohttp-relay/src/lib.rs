//! Least-authority RFC 9458 Oblivious HTTP relay.
//!
//! One process exposes one public relay resource and forwards each accepted
//! encapsulated request to exactly one configured HTTPS gateway resource. The
//! relay never receives a gateway HPKE private key, never decapsulates OHTTP,
//! never chooses an upstream from client input, and never forwards client
//! headers or source-address metadata.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod config;
mod network;
mod relay;
mod runtime;
mod tls;

use std::fmt;
use std::io;

pub use config::{Config, CONFIG_VERSION};
pub use runtime::{
    check_configuration, inspect_configuration, probe_health, run, RelayServiceKeyInfo,
};

/// OHTTP relay result type.
pub type Result<T> = core::result::Result<T, RelayError>;

/// Fail-closed relay error.
#[derive(Debug)]
pub enum RelayError {
    /// A local I/O operation failed.
    Io(io::Error),
    /// Strict configuration validation failed.
    Configuration(String),
    /// A local protocol or runtime invariant failed.
    Invalid(&'static str),
    /// The fixed upstream gateway did not produce an acceptable response.
    Upstream,
}

impl fmt::Display for RelayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O failure: {error}"),
            Self::Configuration(message) => write!(formatter, "{message}"),
            Self::Invalid(message) => write!(formatter, "{message}"),
            Self::Upstream => write!(formatter, "fixed OHTTP gateway unavailable"),
        }
    }
}

impl std::error::Error for RelayError {}

impl From<io::Error> for RelayError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
