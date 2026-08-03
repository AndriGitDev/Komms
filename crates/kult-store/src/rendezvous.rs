//! Sealed, non-backup ADR-0018 service state.
//!
//! One row is bound to one physical-device ratchet session. The exporter is
//! stored separately from the ratchet row, and every route, generation and
//! retry field for that relationship is replaced as one authenticated row.

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use kult_crypto::{rendezvous_provider_id, Session, MAX_RENDEZVOUS_PROVIDER_ORIGIN_BYTES};
use kult_protocol::{RendezvousRouteKind, MAX_RENDEZVOUS_ROUTES, MAX_RENDEZVOUS_ROUTE_BYTES};

use crate::{decode_exact, store_v2, Result, Store, StoreError};

/// Current sealed service-state version.
pub const RENDEZVOUS_SERVICE_STATE_VERSION: u8 = 1;
/// Maximum source rows retained for one physical relationship: up to eight
/// local publication providers plus eight independently selected by the peer.
pub const MAX_RENDEZVOUS_PROVIDERS_PER_SESSION: usize = 16;
/// Maximum encoded service-state bytes per physical relationship.
pub const MAX_RENDEZVOUS_SERVICE_STATE_BYTES: usize = 16 * 1024;
/// Maximum recipient-selected providers in one complete local configuration.
pub const MAX_RENDEZVOUS_LOCAL_PROVIDERS: usize = 8;
/// Current sealed local-provider configuration version.
pub const RENDEZVOUS_LOCAL_CONFIG_VERSION: u8 = 1;
/// Maximum encoded local-provider configuration bytes.
pub const MAX_RENDEZVOUS_LOCAL_CONFIG_BYTES: usize = 8 * 1024;

/// One provider in the sealed complete local configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RendezvousLocalProvider {
    /// Canonical HTTPS origin.
    pub origin: String,
    /// Provider service static key.
    pub static_key: [u8; 32],
    /// Provider-separation id bound to the origin and key.
    pub provider_id: [u8; 32],
}

impl RendezvousLocalProvider {
    fn validate(&self) -> Result<()> {
        if self.origin.is_empty()
            || self.origin.len() > MAX_RENDEZVOUS_PROVIDER_ORIGIN_BYTES
            || self.origin.as_bytes().contains(&0)
            || self.static_key == [0u8; 32]
            || rendezvous_provider_id(self.origin.as_bytes(), &self.static_key)
                .map_err(StoreError::from)?
                != self.provider_id
        {
            return Err(StoreError::RecordBounds);
        }
        Ok(())
    }
}

impl Drop for RendezvousLocalProvider {
    fn drop(&mut self) {
        self.origin.zeroize();
    }
}

/// Sealed singleton source of truth for the complete local provider set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RendezvousLocalConfig {
    /// Storage format version.
    pub version: u8,
    /// Strictly increasing authenticated provider-set generation.
    pub generation: u64,
    /// Complete canonical provider set.
    pub providers: Vec<RendezvousLocalProvider>,
}

impl RendezvousLocalConfig {
    /// Construct and canonically sort one complete bounded configuration.
    pub fn new(generation: u64, providers: Vec<(String, [u8; 32])>) -> Result<Self> {
        let mut providers = providers
            .into_iter()
            .map(|(origin, static_key)| {
                let provider_id = rendezvous_provider_id(origin.as_bytes(), &static_key)
                    .map_err(StoreError::from)?;
                Ok(RendezvousLocalProvider {
                    origin,
                    static_key,
                    provider_id,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        providers.sort_by(|left, right| {
            (left.origin.as_str(), left.static_key).cmp(&(right.origin.as_str(), right.static_key))
        });
        let config = Self {
            version: RENDEZVOUS_LOCAL_CONFIG_VERSION,
            generation,
            providers,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.version != RENDEZVOUS_LOCAL_CONFIG_VERSION
            || self.generation == 0
            || self.providers.len() > MAX_RENDEZVOUS_LOCAL_PROVIDERS
        {
            return Err(StoreError::Serialization);
        }
        for (index, provider) in self.providers.iter().enumerate() {
            provider.validate()?;
            if self.providers[..index].last().is_some_and(|prior| {
                (prior.origin.as_str(), prior.static_key)
                    >= (provider.origin.as_str(), provider.static_key)
            }) || self.providers[..index]
                .iter()
                .any(|prior| prior.provider_id == provider.provider_id)
            {
                return Err(StoreError::Serialization);
            }
        }
        let encoded =
            Zeroizing::new(postcard::to_allocvec(self).map_err(|_| StoreError::Serialization)?);
        if encoded.len() > MAX_RENDEZVOUS_LOCAL_CONFIG_BYTES {
            return Err(StoreError::RecordBounds);
        }
        Ok(())
    }
}

/// One accepted source-scoped rendezvous route.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RendezvousStoredRoute {
    /// Protocol route kind.
    pub kind: u8,
    /// Canonical UTF-8 route bytes.
    pub value: Vec<u8>,
}

impl RendezvousStoredRoute {
    /// Create a bounded stored route from an authenticated protocol route.
    pub fn new(kind: RendezvousRouteKind, value: &[u8]) -> Result<Self> {
        if value.is_empty()
            || value.len() > MAX_RENDEZVOUS_ROUTE_BYTES
            || value.contains(&0)
            || core::str::from_utf8(value).is_err()
        {
            return Err(StoreError::RecordBounds);
        }
        Ok(Self {
            kind: kind as u8,
            value: value.to_vec(),
        })
    }

    /// Decode the retained protocol kind.
    pub fn route_kind(&self) -> Result<RendezvousRouteKind> {
        match self.kind {
            value if value == RendezvousRouteKind::Multiaddr as u8 => {
                Ok(RendezvousRouteKind::Multiaddr)
            }
            value if value == RendezvousRouteKind::MailboxRelay as u8 => {
                Ok(RendezvousRouteKind::MailboxRelay)
            }
            _ => Err(StoreError::Serialization),
        }
    }

    fn validate(&self) -> Result<()> {
        let _ = self.route_kind()?;
        if self.value.is_empty()
            || self.value.len() > MAX_RENDEZVOUS_ROUTE_BYTES
            || self.value.contains(&0)
            || core::str::from_utf8(&self.value).is_err()
        {
            return Err(StoreError::RecordBounds);
        }
        Ok(())
    }
}

impl Drop for RendezvousStoredRoute {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

/// Per-provider generation, lease and bounded retry state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RendezvousProviderState {
    /// Provider id derived from canonical origin and static key.
    pub provider_id: [u8; 32],
    /// Canonical provider HTTPS origin.
    pub origin: String,
    /// Provider service static key.
    pub static_key: [u8; 32],
    /// Whether this device publishes its own direction to this provider.
    pub publish_enabled: bool,
    /// Whether this device looks up the contact direction at this provider.
    pub lookup_enabled: bool,
    /// Last generation durably reserved for publication.
    pub publish_generation: u64,
    /// Greatest authenticated generation accepted from this provider.
    pub accepted_generation: u64,
    /// Greatest generation at which distinct valid complete records were
    /// observed. That generation remains fail-closed until a strictly newer
    /// authenticated record is accepted.
    #[serde(default)]
    pub conflict_generation: Option<u64>,
    /// Greatest effective wall-clock value observed while accepting a record.
    pub clock_floor: u64,
    /// Expiry of the currently accepted route source.
    pub routes_expires_at: u64,
    /// Complete current rendezvous route set; an empty set revokes this source.
    pub routes: Vec<RendezvousStoredRoute>,
    /// Last time a self-lookup confirmed a registration.
    pub registration_confirmed_at: u64,
    /// Earliest next registration attempt.
    pub next_register_at: u64,
    /// Earliest next lookup attempt.
    pub next_lookup_at: u64,
    /// Consecutive bounded transport failures.
    pub consecutive_failures: u8,
    /// Circuit-breaker deadline; zero means closed.
    pub circuit_open_until: u64,
    /// A removed local provider still needs one authenticated empty
    /// registration before this source can be forgotten.
    #[serde(default)]
    pub withdrawal_pending: bool,
}

impl RendezvousProviderState {
    /// Fresh provider-specific counters for a newly negotiated session.
    pub fn new(provider_id: [u8; 32], origin: String, static_key: [u8; 32]) -> Self {
        Self {
            provider_id,
            origin,
            static_key,
            publish_enabled: false,
            lookup_enabled: false,
            publish_generation: 0,
            accepted_generation: 0,
            conflict_generation: None,
            clock_floor: 0,
            routes_expires_at: 0,
            routes: Vec::new(),
            registration_confirmed_at: 0,
            next_register_at: 0,
            next_lookup_at: 0,
            consecutive_failures: 0,
            circuit_open_until: 0,
            withdrawal_pending: false,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.origin.is_empty()
            || self.origin.len() > MAX_RENDEZVOUS_PROVIDER_ORIGIN_BYTES
            || self.origin.as_bytes().contains(&0)
            || self.static_key == [0u8; 32]
            || rendezvous_provider_id(self.origin.as_bytes(), &self.static_key)
                .map_err(StoreError::from)?
                != self.provider_id
            || self.routes.len() > MAX_RENDEZVOUS_ROUTES
            || self
                .conflict_generation
                .is_some_and(|generation| generation < self.accepted_generation)
        {
            return Err(StoreError::RecordBounds);
        }
        for (index, route) in self.routes.iter().enumerate() {
            route.validate()?;
            if self.routes[..index].contains(route) {
                return Err(StoreError::Serialization);
            }
        }
        if self.routes.is_empty() && self.routes_expires_at != 0 {
            return Err(StoreError::Serialization);
        }
        Ok(())
    }
}

impl Drop for RendezvousProviderState {
    fn drop(&mut self) {
        self.origin.zeroize();
    }
}

/// Complete relationship-scoped optional-service state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RendezvousServiceState {
    /// Storage format version.
    pub version: u8,
    /// Exact handshake transcript id owning this exporter.
    pub session_id: [u8; 32],
    /// Exporter derived alongside the verified PQXDH root.
    pub hybrid_service_exporter: [u8; 32],
    /// Greatest authenticated remote provider-set generation.
    pub remote_provider_generation: u64,
    /// Greatest remote provider-set generation observed with distinct valid
    /// complete contents. Lookup stays disabled until a strictly newer
    /// authenticated complete set arrives.
    #[serde(default)]
    pub remote_provider_conflict_generation: Option<u64>,
    /// Bounded provider-specific state.
    pub providers: Vec<RendezvousProviderState>,
}

impl RendezvousServiceState {
    fn fresh(session: &Session, exporter: [u8; 32]) -> Self {
        Self {
            version: RENDEZVOUS_SERVICE_STATE_VERSION,
            session_id: *session.session_id(),
            hybrid_service_exporter: exporter,
            remote_provider_generation: 0,
            remote_provider_conflict_generation: None,
            providers: Vec::new(),
        }
    }

    /// Get or create one bounded provider state.
    pub fn provider_mut(
        &mut self,
        provider_id: [u8; 32],
        origin: String,
        static_key: [u8; 32],
    ) -> Result<&mut RendezvousProviderState> {
        if let Some(index) = self
            .providers
            .iter()
            .position(|state| state.provider_id == provider_id)
        {
            if self.providers[index].origin != origin
                || self.providers[index].static_key != static_key
            {
                return Err(StoreError::LogicalKeyMismatch);
            }
            return Ok(&mut self.providers[index]);
        }
        if self.providers.len() >= MAX_RENDEZVOUS_PROVIDERS_PER_SESSION {
            return Err(StoreError::RecordBounds);
        }
        self.providers.push(RendezvousProviderState::new(
            provider_id,
            origin,
            static_key,
        ));
        self.providers.last_mut().ok_or(StoreError::Serialization)
    }

    /// Read one provider state.
    pub fn provider(&self, provider_id: &[u8; 32]) -> Option<&RendezvousProviderState> {
        self.providers
            .iter()
            .find(|state| &state.provider_id == provider_id)
    }

    fn validate(&self) -> Result<()> {
        if self.version != RENDEZVOUS_SERVICE_STATE_VERSION
            || self.providers.len() > MAX_RENDEZVOUS_PROVIDERS_PER_SESSION
            || self
                .remote_provider_conflict_generation
                .is_some_and(|generation| generation < self.remote_provider_generation)
        {
            return Err(StoreError::Serialization);
        }
        for (index, provider) in self.providers.iter().enumerate() {
            provider.validate()?;
            if self.providers[..index]
                .iter()
                .any(|prior| prior.provider_id == provider.provider_id)
            {
                return Err(StoreError::Serialization);
            }
        }
        let encoded =
            Zeroizing::new(postcard::to_allocvec(self).map_err(|_| StoreError::Serialization)?);
        if encoded.len() > MAX_RENDEZVOUS_SERVICE_STATE_BYTES {
            return Err(StoreError::RecordBounds);
        }
        Ok(())
    }
}

impl Drop for RendezvousServiceState {
    fn drop(&mut self) {
        self.hybrid_service_exporter.zeroize();
    }
}

impl Store {
    /// Load the separately sealed complete local provider configuration.
    pub fn get_rendezvous_local_config(&self) -> Result<Option<RendezvousLocalConfig>> {
        let config = self
            .get_equality::<store_v2::RendezvousConfigRows>(&store_v2::SingletonKey)?
            .map(|row| decode_exact::<RendezvousLocalConfig>(&row.payload))
            .transpose()?;
        if let Some(config) = config.as_ref() {
            config.validate()?;
        }
        Ok(config)
    }

    /// Atomically replace the complete local provider configuration.
    pub fn put_rendezvous_local_config(
        &self,
        config: &RendezvousLocalConfig,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        config.validate()?;
        let encoded =
            Zeroizing::new(postcard::to_allocvec(config).map_err(|_| StoreError::Serialization)?);
        self.put_equality::<store_v2::RendezvousConfigRows>(
            &store_v2::SingletonKey,
            &encoded,
            store_v2::IndexKeys::none(),
            rng,
        )
    }

    pub(crate) fn validate_rendezvous_logical_rows(&self) -> Result<()> {
        self.validate_rows::<store_v2::RendezvousConfigRows, _>(|row| {
            row.verify_key(&store_v2::SingletonKey)?;
            row.verify_indexes(&store_v2::IndexKeys::none())?;
            let config: RendezvousLocalConfig = decode_exact(&row.payload)?;
            config.validate()
        })?;
        self.validate_rows::<store_v2::RendezvousServiceRows, _>(|row| {
            let _ = store_v2::AccountKey::decode(&row.logical_key)?;
            row.verify_indexes(&store_v2::IndexKeys::none())?;
            let state: RendezvousServiceState = decode_exact(&row.payload)?;
            state.validate()
        })
    }

    pub(crate) fn synchronize_rendezvous_session(
        &self,
        peer: &[u8; 32],
        session: &Session,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let Some(exporter) = session.hybrid_service_exporter() else {
            self.delete_equality::<store_v2::RendezvousServiceRows>(&store_v2::AccountKey::new(
                *peer,
            ))?;
            return Ok(());
        };
        let current = self.get_rendezvous_service_state(peer)?;
        if current.as_ref().is_some_and(|state| {
            state.session_id == *session.session_id() && state.hybrid_service_exporter == *exporter
        }) {
            return Ok(());
        }
        self.write_rendezvous_service_state(
            peer,
            &RendezvousServiceState::fresh(session, *exporter),
            rng,
        )
    }

    /// Load separately sealed relationship service state.
    pub fn get_rendezvous_service_state(
        &self,
        peer: &[u8; 32],
    ) -> Result<Option<RendezvousServiceState>> {
        let state = self
            .get_equality::<store_v2::RendezvousServiceRows>(&store_v2::AccountKey::new(*peer))?
            .map(|row| decode_exact::<RendezvousServiceState>(&row.payload))
            .transpose()?;
        if let Some(state) = state.as_ref() {
            state.validate()?;
        }
        Ok(state)
    }

    /// Replace one complete sealed service-state row.
    pub fn put_rendezvous_service_state(
        &self,
        peer: &[u8; 32],
        state: &RendezvousServiceState,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        state.validate()?;
        let session = self.get_session_ratchet(peer)?;
        if session
            .as_ref()
            .is_none_or(|session| state.session_id != *session.session_id())
        {
            return Err(StoreError::LogicalKeyMismatch);
        }
        self.write_rendezvous_service_state(peer, state, rng)
    }

    fn write_rendezvous_service_state(
        &self,
        peer: &[u8; 32],
        state: &RendezvousServiceState,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        state.validate()?;
        let encoded =
            Zeroizing::new(postcard::to_allocvec(state).map_err(|_| StoreError::Serialization)?);
        self.put_equality::<store_v2::RendezvousServiceRows>(
            &store_v2::AccountKey::new(*peer),
            &encoded,
            store_v2::IndexKeys::none(),
            rng,
        )
    }

    pub(crate) fn delete_rendezvous_service_state(&self, peer: &[u8; 32]) -> Result<()> {
        self.delete_equality::<store_v2::RendezvousServiceRows>(&store_v2::AccountKey::new(*peer))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use kult_crypto::{
        initiate, Identity, KdfProfile, OneTimePrekeySecret, PqPrekeySecret, PrekeyBundle,
        SignedPrekeySecret,
    };
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    const TEST_KDF: KdfProfile = KdfProfile {
        m_cost_kib: 8,
        t_cost: 1,
        p_cost: 1,
    };
    const NOW: u64 = 1_800_000_000;

    fn session(rng: &mut StdRng) -> Session {
        let initiator = Identity::generate(rng);
        let responder = Identity::generate(rng);
        let spk = SignedPrekeySecret::generate(rng, 1);
        let pqspk = PqPrekeySecret::generate(rng, 2);
        let opk = OneTimePrekeySecret::generate(rng, 3);
        let bundle =
            PrekeyBundle::build(&responder, &spk, &pqspk, Some(&opk), NOW + 86_400, vec![])
                .verify(NOW)
                .unwrap();
        initiate(&initiator, &bundle, b"first", NOW, rng).unwrap().0
    }

    #[test]
    fn exporter_is_separate_persistent_nonportable_and_session_bound() {
        let mut rng = StdRng::seed_from_u64(0x18_51);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rendezvous.db");
        let store = Store::create(&path, b"pass", TEST_KDF, &mut rng).unwrap();
        let local_config =
            RendezvousLocalConfig::new(3, vec![("https://rv.example".to_owned(), [4u8; 32])])
                .unwrap();
        store
            .put_rendezvous_local_config(&local_config, &mut rng)
            .unwrap();
        assert_eq!(
            store.get_rendezvous_local_config().unwrap(),
            Some(local_config.clone())
        );
        let peer = [9u8; 32];
        let first = session(&mut rng);
        let exporter = *first.hybrid_service_exporter().unwrap();
        store.put_session(&peer, &first, &mut rng).unwrap();

        let state = store.get_rendezvous_service_state(&peer).unwrap().unwrap();
        assert_eq!(state.session_id, *first.session_id());
        assert_eq!(state.hybrid_service_exporter, exporter);
        assert_eq!(
            *store
                .get_session(&peer)
                .unwrap()
                .unwrap()
                .hybrid_service_exporter()
                .unwrap(),
            exporter
        );

        let mut updated = state;
        let origin = "https://rv.example".to_owned();
        let key = [4u8; 32];
        let provider_id = rendezvous_provider_id(origin.as_bytes(), &key).unwrap();
        updated
            .provider_mut(provider_id, origin, key)
            .unwrap()
            .publish_generation = 7;
        store
            .put_rendezvous_service_state(&peer, &updated, &mut rng)
            .unwrap();
        store.put_session(&peer, &first, &mut rng).unwrap();
        assert_eq!(
            store
                .get_rendezvous_service_state(&peer)
                .unwrap()
                .unwrap()
                .provider(&provider_id)
                .unwrap()
                .publish_generation,
            7
        );

        let replacement = session(&mut rng);
        store.put_session(&peer, &replacement, &mut rng).unwrap();
        let reset = store.get_rendezvous_service_state(&peer).unwrap().unwrap();
        assert_eq!(reset.session_id, *replacement.session_id());
        assert!(reset.providers.is_empty());

        drop(store);
        let reopened = Store::open(&path, b"pass").unwrap();
        assert_eq!(
            reopened.get_rendezvous_local_config().unwrap(),
            Some(local_config)
        );
        assert!(reopened
            .get_session(&peer)
            .unwrap()
            .unwrap()
            .hybrid_service_exporter()
            .is_some());
        reopened.delete_session(&peer).unwrap();
        assert!(reopened
            .get_rendezvous_service_state(&peer)
            .unwrap()
            .is_none());
    }

    #[test]
    fn legacy_session_without_exporter_clears_optional_service_authority() {
        let mut rng = StdRng::seed_from_u64(0x18_52);
        let dir = tempfile::tempdir().unwrap();
        let store =
            Store::create(&dir.path().join("legacy.db"), b"pass", TEST_KDF, &mut rng).unwrap();
        let peer = [8u8; 32];
        let current = session(&mut rng);
        store.put_session(&peer, &current, &mut rng).unwrap();
        assert!(store.get_rendezvous_service_state(&peer).unwrap().is_some());

        let mut legacy = current;
        legacy.restore_hybrid_service_exporter(None);
        store.put_session(&peer, &legacy, &mut rng).unwrap();
        assert!(store.get_rendezvous_service_state(&peer).unwrap().is_none());
        assert!(store
            .get_session(&peer)
            .unwrap()
            .unwrap()
            .hybrid_service_exporter()
            .is_none());
    }
}
