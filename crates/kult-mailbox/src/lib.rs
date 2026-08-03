//! Dedicated least-authority durable mailbox-v2 service.
//!
//! The binary has one application role and negotiates only
//! `/komms/mailbox/2`. It carries opaque sealed envelopes under bounded
//! durable leases and has no account, endpoint, DHT, rendezvous, wake,
//! directory, update, analytics, bridge, or mailbox-v1 authority.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod config;
mod runtime;

pub use config::{Config, CONFIG_VERSION, DEFAULT_SOURCE_REVISION};
pub use runtime::{
    initialize, inspect, probe_health, run, MailboxError, MailboxServiceInspection, Result,
};
