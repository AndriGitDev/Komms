//! Least-authority ADR-0019 native-wake gateway component.
//!
//! The component opens fixed-width opaque capabilities, enforces bounded
//! replay/revocation and quota state, and hands only static notification
//! profiles plus native routing state to a narrowly scoped provider boundary.
//! It receives no Komms identity, conversation, message, media, or receipt
//! data.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod config;
mod keys;
mod native_provider;
mod network;
mod provider;
mod runtime;
mod service;
mod state;

pub use config::{Config, CONFIG_VERSION, DEFAULT_SOURCE_REVISION};
pub use keys::{
    generate_capability_key, CapabilityKeyProvider, FileCapabilityKeyring, WakeKeyMetadata,
};
pub use network::{run_tls_gateway, WakeNetworkConfig};
pub use provider::{
    NativePushProvider, NativePushRequest, ProviderErrorClass, APNS_BACKGROUND_PAYLOAD,
    APNS_GENERIC_PAYLOAD, FCM_BACKGROUND_PAYLOAD, FCM_GENERIC_PAYLOAD,
};
pub use runtime::{
    check_configuration, inspect_configuration, probe_health, run, WakeServiceKeyInfo,
};
pub use service::{GatewayLimits, GatewayMetrics, WakeGateway};
pub use state::{GatewayStateCounts, GatewayStateStore};

/// Errors surfaced by the bounded gateway component.
#[derive(Debug)]
#[non_exhaustive]
pub enum WakeError {
    /// Configuration or fixed-shape input was invalid.
    Invalid(&'static str),
    /// Strict configuration or credential metadata was invalid.
    Configuration(String),
    /// A gateway key operation failed.
    Key,
    /// Durable replay/revocation state failed.
    State(rusqlite::Error),
    /// Local key or state I/O failed.
    Io(std::io::Error),
}

impl core::fmt::Display for WakeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::Configuration(message) => formatter.write_str(message),
            Self::Key => formatter.write_str("wake capability key operation failed"),
            Self::State(error) => write!(formatter, "wake state error: {error}"),
            Self::Io(error) => write!(formatter, "wake state I/O error: {error}"),
        }
    }
}

impl std::error::Error for WakeError {}

impl From<rusqlite::Error> for WakeError {
    fn from(error: rusqlite::Error) -> Self {
        Self::State(error)
    }
}

impl From<std::io::Error> for WakeError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// Convenience result.
pub type Result<T> = core::result::Result<T, WakeError>;
