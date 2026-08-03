//! Authenticated post-pairing discovery and route upgrades (ADR-0031).
//!
//! These controls travel only inside an established pairwise ratchet. They
//! let existing contacts and group co-members learn a rotated Connect
//! capability without returning to identity-indexed public discovery.

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::{ProtocolError, Result};

/// Receipt-lane prefix for a discovery upgrade control.
pub const DISCOVERY_UPGRADE_MAGIC: [u8; 6] = [0x00, 0x00, 0xff, b'K', b'D', b'C'];
/// Current authenticated discovery-control version.
pub const DISCOVERY_UPGRADE_VERSION: u8 = 1;
/// Maximum relationship-scoped route hints in one upgrade.
pub const MAX_DISCOVERY_UPGRADE_ROUTES: usize = 8;
/// Maximum encoded bytes in one relationship-scoped route hint.
pub const MAX_DISCOVERY_UPGRADE_ROUTE_BYTES: usize = 4096;

/// Complete account-scoped capability and current authenticated routes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryUpgradeControl {
    /// Stable account whose active device sent this control.
    pub account: [u8; 32],
    /// Random rotatable reachability capability.
    pub capability: [u8; 32],
    /// Monotonic capability/publication generation.
    pub generation: u64,
    /// Authority generation accepted by the sender.
    pub authority_generation: u64,
    /// Whether `routes` is a complete replacement. When false, the control
    /// upgrades only the capability and must carry no routes.
    pub routes_complete: bool,
    /// Canonical higher-layer route values, sorted and unique.
    pub routes: Vec<Vec<u8>>,
}

impl DiscoveryUpgradeControl {
    /// Encode one bounded canonical encrypted control.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let body = postcard::to_allocvec(self).map_err(|_| ProtocolError::Malformed)?;
        let mut out = Vec::with_capacity(DISCOVERY_UPGRADE_MAGIC.len() + 1 + body.len());
        out.extend_from_slice(&DISCOVERY_UPGRADE_MAGIC);
        out.push(DISCOVERY_UPGRADE_VERSION);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Strictly decode and validate a complete control.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let body = bytes
            .strip_prefix(&DISCOVERY_UPGRADE_MAGIC)
            .and_then(|bytes| bytes.strip_prefix(&[DISCOVERY_UPGRADE_VERSION]))
            .ok_or(ProtocolError::Malformed)?;
        let (control, remainder): (Self, &[u8]) =
            postcard::take_from_bytes(body).map_err(|_| ProtocolError::Malformed)?;
        if !remainder.is_empty() {
            return Err(ProtocolError::Malformed);
        }
        control.validate()?;
        Ok(control)
    }

    fn validate(&self) -> Result<()> {
        if self.account == [0u8; 32]
            || self.capability == [0u8; 32]
            || self.generation == 0
            || self.authority_generation == 0
            || (!self.routes_complete && !self.routes.is_empty())
            || self.routes.len() > MAX_DISCOVERY_UPGRADE_ROUTES
            || self
                .routes
                .iter()
                .any(|route| route.is_empty() || route.len() > MAX_DISCOVERY_UPGRADE_ROUTE_BYTES)
            || self.routes.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(ProtocolError::Malformed);
        }
        Ok(())
    }
}

/// Whether decrypted receipt-lane bytes use the discovery-control prefix.
pub fn is_discovery_upgrade_control(bytes: &[u8]) -> bool {
    bytes.starts_with(&DISCOVERY_UPGRADE_MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_bounds_and_canonical_routes() {
        let control = DiscoveryUpgradeControl {
            account: [1; 32],
            capability: [2; 32],
            generation: 3,
            authority_generation: 4,
            routes_complete: true,
            routes: vec![b"a".to_vec(), b"b".to_vec()],
        };
        let encoded = control.encode().unwrap();
        assert!(is_discovery_upgrade_control(&encoded));
        assert_eq!(DiscoveryUpgradeControl::decode(&encoded).unwrap(), control);

        let mut capability_only_with_routes = control.clone();
        capability_only_with_routes.routes_complete = false;
        assert_eq!(
            capability_only_with_routes.encode(),
            Err(ProtocolError::Malformed)
        );

        let mut duplicate = control;
        duplicate.routes = vec![b"a".to_vec(), b"a".to_vec()];
        assert_eq!(duplicate.encode(), Err(ProtocolError::Malformed));
    }

    #[test]
    fn malformed_and_trailing_values_fail_closed() {
        let control = DiscoveryUpgradeControl {
            account: [1; 32],
            capability: [2; 32],
            generation: 3,
            authority_generation: 4,
            routes_complete: false,
            routes: Vec::new(),
        };
        let mut trailing = control.encode().unwrap();
        trailing.push(0);
        assert_eq!(
            DiscoveryUpgradeControl::decode(&trailing),
            Err(ProtocolError::Malformed)
        );
        assert_eq!(
            DiscoveryUpgradeControl::decode(b"not-a-control"),
            Err(ProtocolError::Malformed)
        );
    }
}
