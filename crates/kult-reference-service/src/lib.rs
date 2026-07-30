//! Operator-minimized Komms reference discovery service.
//!
//! The crate intentionally exposes exactly two network roles: a bounded
//! in-memory libp2p bootstrap/Kademlia cache and the fixed-shape ADR-0018
//! rendezvous service. It has no endpoint, mailbox, wake, directory, update,
//! analytics, bridge, contact, account, or message interface.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod config;
mod dht;
mod http;
mod keys;
mod runtime;

pub use config::{
    Config, DhtConfig, RendezvousConfig, RuntimeLimits, CONFIG_VERSION, DEFAULT_SOURCE_REVISION,
};
pub use dht::{DhtMetrics, DhtService};
pub use keys::{
    generate_libp2p_identity, inspect_service_keys, load_libp2p_identity, ServiceKeyInfo,
};
pub use runtime::{probe_health, run, HealthSnapshot, ServiceError};
