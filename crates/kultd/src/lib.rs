//! Komms headless daemon (docs/03-architecture.md, application A3).
//!
//! `kultd` runs a full [`kult_node::Node`] over the libp2p internet carrier
//! — delivery engine ticking, DHT bootstrap and prekey-bundle publication,
//! NAT probing with automatic relay-circuit reservation, mailbox check-ins —
//! and exposes the node's command/event API as newline-delimited JSON RPC on
//! a local Unix socket. `kult` (same crate) is the matching command-line
//! client.
//!
//! The daemon adds **no behavior** beyond composing what the lower layers
//! already provide; anything protocol-shaped belongs in `kult-node` or
//! below.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod daemon;
mod secret;
pub mod wire;

pub use daemon::{Daemon, DaemonConfig, DaemonError};
pub use secret::read_secret_file;
