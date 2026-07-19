//! Stable, time-bounded per-peer carrier verdicts (feature plan F4).

use std::sync::Arc;

use rand_core::CryptoRngCore;

use kult_transport::{CostClass, LatencyClass, Reachability};

use crate::{
    CarrierCapability, CarrierCapabilitySnapshot, Event, Node, NodeError, Result, Transport,
};

/// Carrier observations are advisory and deliberately short-lived. The next
/// node tick refreshes them sooner when the application is active.
const CARRIER_CAPABILITY_TTL_SECS: u64 = 60;

impl Node {
    /// Return a safe carrier snapshot for one stored contact. An expired
    /// positive verdict is downgraded to `offline_or_unknown`; callers never
    /// need to implement their own staleness rule.
    pub fn carrier_capability(
        &self,
        peer: &[u8; 32],
        now: u64,
    ) -> Result<CarrierCapabilitySnapshot> {
        if self.store.get_contact(peer)?.is_none() {
            return Err(NodeError::UnknownPeer);
        }
        let Some(snapshot) = self.carrier_capabilities.get(peer).copied() else {
            return Ok(offline_snapshot(*peer, now, now));
        };
        if now < snapshot.expires_at {
            Ok(snapshot)
        } else {
            Ok(offline_snapshot(
                snapshot.peer,
                snapshot.observed_at,
                snapshot.expires_at,
            ))
        }
    }

    /// Return safe snapshots for every stored contact, ordered like
    /// [`Node::contacts`].
    pub fn carrier_capabilities(&self, now: u64) -> Result<Vec<CarrierCapabilitySnapshot>> {
        self.store
            .contacts()?
            .into_iter()
            .map(|contact| self.carrier_capability(&contact.peer, now))
            .collect()
    }

    pub(crate) fn carrier_allows_bulk(&self, peer: &[u8; 32], now: u64) -> Result<bool> {
        Ok(matches!(
            self.carrier_capability(peer, now)?.capability,
            CarrierCapability::Realtime | CarrierCapability::Bulk
        ))
    }

    pub(crate) async fn refresh_carrier_capabilities(
        &mut self,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let peers: Vec<[u8; 32]> = self
            .store
            .contacts()?
            .into_iter()
            .map(|contact| contact.peer)
            .collect();
        let transports = self.transports.clone();

        for peer in peers {
            // Capability classification reads the stored route; stale-hint
            // refresh stays owned by the delivery engine's failure signal.
            let hints = self.resolve_hints(&peer, now, false, rng).await?;
            let capability = classify(&transports, &hints).await;
            let snapshot = CarrierCapabilitySnapshot {
                peer,
                capability,
                observed_at: now,
                expires_at: now.saturating_add(CARRIER_CAPABILITY_TTL_SECS),
            };
            let changed = self
                .carrier_capabilities
                .get(&peer)
                .is_none_or(|previous| previous.capability != capability);
            self.carrier_capabilities.insert(peer, snapshot);
            if changed {
                self.events
                    .push_back(Event::CarrierCapabilityChanged { snapshot });
            }
        }
        Ok(())
    }
}

async fn classify(
    transports: &[Arc<dyn Transport>],
    hints: &[kult_transport::DeliveryHint],
) -> CarrierCapability {
    let mut bulk = false;
    let mut mesh = false;
    for transport in transports {
        let profile = transport.profile();
        for hint in hints {
            let reachability = transport.reachable(hint).await;
            if reachability == Reachability::Unreachable {
                continue;
            }
            if profile.cost == CostClass::Airtime {
                mesh = true;
            } else if profile.latency == LatencyClass::Millis
                && reachability == Reachability::Now
                && transport.call_ready(hint)
            {
                return CarrierCapability::Realtime;
            } else {
                bulk = true;
            }
        }
    }
    if bulk {
        CarrierCapability::Bulk
    } else if mesh {
        CarrierCapability::MeshOnly
    } else {
        CarrierCapability::OfflineOrUnknown
    }
}

fn offline_snapshot(
    peer: [u8; 32],
    observed_at: u64,
    expires_at: u64,
) -> CarrierCapabilitySnapshot {
    CarrierCapabilitySnapshot {
        peer,
        capability: CarrierCapability::OfflineOrUnknown,
        observed_at,
        expires_at,
    }
}
