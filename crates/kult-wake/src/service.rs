use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use hmac::{Hmac, Mac};
use rand_core::CryptoRngCore;
use sha2::Sha256;
use zeroize::Zeroize;

use kult_protocol::{
    wake_generic_response, WakeCapability, WakeCapabilityPayload, WakeRegisterRequest,
    WakeRegisterResponse, WakeTriggerRequest, WAKE_CAPABILITY_ASSOCIATED_DATA,
    WAKE_CAPABILITY_MAX_LIFETIME_SECS, WAKE_CAPABILITY_PLAINTEXT_LEN, WAKE_GENERIC_RESPONSE_LEN,
};

use crate::keys::CapabilityKeyProvider;
use crate::provider::{NativePushProvider, NativePushRequest, ProviderErrorClass};
use crate::state::{Authorization, GatewayStateCounts, GatewayStateStore};
use crate::{Result, WakeError};

type HmacSha256 = Hmac<Sha256>;

/// Bounded gateway capacity and abuse policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayLimits {
    /// Lifetime assigned to newly issued capabilities.
    pub capability_lifetime_secs: u64,
    /// Accepted trigger requests per capability in one fixed minute.
    pub per_capability_per_minute: u32,
    /// Accepted trigger requests per native destination in one fixed minute.
    pub per_destination_per_minute: u32,
    /// Provider operations across the gateway in one fixed minute.
    pub global_per_minute: u32,
    /// Maximum in-memory capability quota buckets.
    pub max_capability_buckets: usize,
    /// Maximum in-memory destination quota/coalescing buckets.
    pub max_destination_buckets: usize,
    /// Native operations for one destination collapse inside this interval.
    pub coalesce_seconds: u64,
    /// Hard deadline for one native-provider operation.
    pub provider_timeout: Duration,
}

impl Default for GatewayLimits {
    fn default() -> Self {
        Self {
            capability_lifetime_secs: WAKE_CAPABILITY_MAX_LIFETIME_SECS,
            per_capability_per_minute: 6,
            per_destination_per_minute: 12,
            global_per_minute: 10_000,
            max_capability_buckets: 65_536,
            max_destination_buckets: 65_536,
            coalesce_seconds: 30,
            provider_timeout: Duration::from_secs(10),
        }
    }
}

impl GatewayLimits {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.capability_lifetime_secs == 0
            || self.capability_lifetime_secs > WAKE_CAPABILITY_MAX_LIFETIME_SECS
            || self.per_capability_per_minute == 0
            || self.per_destination_per_minute == 0
            || self.global_per_minute == 0
            || self.max_capability_buckets == 0
            || self.max_destination_buckets == 0
            || self.max_capability_buckets > 1_000_000
            || self.max_destination_buckets > 1_000_000
            || self.coalesce_seconds == 0
            || self.coalesce_seconds > 300
            || self.provider_timeout.is_zero()
            || self.provider_timeout > Duration::from_secs(60)
        {
            return Err(WakeError::Invalid("wake gateway limits are invalid"));
        }
        Ok(())
    }
}

/// Content-free aggregate gateway metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GatewayMetrics {
    /// Capabilities issued.
    pub capabilities_issued: u64,
    /// Fixed-shape registration refusals.
    pub registrations_refused: u64,
    /// Syntactically malformed trigger/revoke requests.
    pub malformed_requests: u64,
    /// Capabilities that failed to open or validate.
    pub invalid_capabilities: u64,
    /// Expired capability attempts.
    pub expired_capabilities: u64,
    /// Revoked capability attempts.
    pub revoked_capabilities: u64,
    /// Duplicate request nonces.
    pub replayed_requests: u64,
    /// Requests coalesced by destination.
    pub coalesced_requests: u64,
    /// Requests suppressed by a bounded quota.
    pub rate_limited_requests: u64,
    /// Provider operations accepted.
    pub provider_successes: u64,
    /// Temporary provider failures.
    pub provider_unavailable: u64,
    /// Provider overload/rate failures.
    pub provider_rate_limited: u64,
    /// Provider credential failures.
    pub provider_authentication: u64,
    /// Invalid native destinations retired.
    pub provider_invalid_destination: u64,
    /// Other provider failures.
    pub provider_other: u64,
    /// Capabilities successfully revoked.
    pub capabilities_revoked: u64,
}

#[derive(Clone, Copy, Debug)]
struct Window {
    minute: u64,
    count: u32,
}

#[derive(Default)]
struct RuntimeState {
    capability: HashMap<[u8; 16], Window>,
    destination: HashMap<[u8; 32], Window>,
    coalesced_until: HashMap<[u8; 32], u64>,
    global: Option<Window>,
}

/// Fixed-shape wake gateway core.
pub struct WakeGateway {
    keys: Arc<dyn CapabilityKeyProvider>,
    durable: Mutex<GatewayStateStore>,
    provider: Arc<dyn NativePushProvider>,
    limits: GatewayLimits,
    runtime: Mutex<RuntimeState>,
    metrics: Mutex<GatewayMetrics>,
    destination_secret: [u8; 32],
}

impl WakeGateway {
    /// Construct a gateway with separate key, state, and provider boundaries.
    pub fn new(
        keys: Arc<dyn CapabilityKeyProvider>,
        durable: GatewayStateStore,
        provider: Arc<dyn NativePushProvider>,
        limits: GatewayLimits,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        limits.validate()?;
        if keys.active_key_id() == 0 {
            return Err(WakeError::Invalid("wake active key id is zero"));
        }
        let mut destination_secret = [0u8; 32];
        rng.fill_bytes(&mut destination_secret);
        if destination_secret == [0u8; 32] {
            return Err(WakeError::Key);
        }
        Ok(Self {
            keys,
            durable: Mutex::new(durable),
            provider,
            limits,
            runtime: Mutex::new(RuntimeState::default()),
            metrics: Mutex::new(GatewayMetrics::default()),
            destination_secret,
        })
    }

    /// Issue one fresh per-contact, per-direction capability.
    ///
    /// Any invalid or unavailable operation returns the same fixed-width
    /// refusal response and retains no native routing state.
    pub fn register(
        &self,
        body: &[u8],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> [u8; kult_protocol::WAKE_REGISTER_RESPONSE_LEN] {
        let response = self
            .try_register(body, now, rng)
            .unwrap_or_else(|_| WakeRegisterResponse::refused())
            .encode()
            .expect("fixed refusal is valid");
        if response[1] == 0 {
            self.update_metrics(|metrics| {
                metrics.registrations_refused = metrics.registrations_refused.saturating_add(1);
            });
        }
        response
    }

    fn try_register(
        &self,
        body: &[u8],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<WakeRegisterResponse> {
        let request =
            WakeRegisterRequest::decode(body).map_err(|_| WakeError::Invalid("register body"))?;
        let expires_at = now
            .checked_add(self.limits.capability_lifetime_secs)
            .ok_or(WakeError::Invalid("wake expiry overflow"))?;
        let mut capability_id = [0u8; 16];
        let mut nonce = [0u8; 24];
        for _ in 0..8 {
            rng.fill_bytes(&mut capability_id);
            rng.fill_bytes(&mut nonce);
            if capability_id != [0u8; 16] && nonce != [0u8; 24] {
                break;
            }
        }
        if capability_id == [0u8; 16] || nonce == [0u8; 24] {
            return Err(WakeError::Key);
        }
        let mut plaintext = WakeCapabilityPayload {
            platform: request.platform,
            environment: request.environment,
            profile: request.profile,
            expires_at,
            capability_id,
            provider_token: request.provider_token,
            app_topic: request.app_topic,
        }
        .encode()
        .map_err(|_| WakeError::Invalid("wake capability payload"))?;
        let sealed = self
            .keys
            .seal_active(&nonce, &plaintext, WAKE_CAPABILITY_ASSOCIATED_DATA)?;
        plaintext.zeroize();
        let capability = WakeCapability::from_parts(self.keys.active_key_id(), nonce, &sealed)
            .map_err(|_| WakeError::Key)?;
        self.update_metrics(|metrics| {
            metrics.capabilities_issued = metrics.capabilities_issued.saturating_add(1);
        });
        WakeRegisterResponse::issued(expires_at, capability)
            .map_err(|_| WakeError::Invalid("wake registration response"))
    }

    /// Process one trigger and always return the same fixed body.
    pub async fn trigger(&self, body: &[u8], now: u64) -> [u8; WAKE_GENERIC_RESPONSE_LEN] {
        let _ = self.try_trigger(body, now).await;
        wake_generic_response()
    }

    async fn try_trigger(&self, body: &[u8], now: u64) -> Result<()> {
        let request = match WakeTriggerRequest::decode(body) {
            Ok(request) => request,
            Err(_) => {
                self.update_metrics(|metrics| {
                    metrics.malformed_requests = metrics.malformed_requests.saturating_add(1);
                });
                return Err(WakeError::Invalid("wake trigger body"));
            }
        };
        let payload = match self.open_capability(&request.capability) {
            Ok(payload) => payload,
            Err(error) => {
                self.update_metrics(|metrics| {
                    metrics.invalid_capabilities = metrics.invalid_capabilities.saturating_add(1);
                });
                return Err(error);
            }
        };
        if payload.expires_at <= now
            || payload.expires_at.saturating_sub(now) > WAKE_CAPABILITY_MAX_LIFETIME_SECS
        {
            self.update_metrics(|metrics| {
                metrics.expired_capabilities = metrics.expired_capabilities.saturating_add(1);
            });
            return Err(WakeError::Invalid("wake capability expired"));
        }
        let authorization = self.lock_durable().authorize(
            &payload.capability_id,
            &request.request_nonce,
            payload.expires_at,
            now,
        )?;
        match authorization {
            Authorization::Fresh => {}
            Authorization::Duplicate => {
                self.update_metrics(|metrics| {
                    metrics.replayed_requests = metrics.replayed_requests.saturating_add(1);
                });
                return Ok(());
            }
            Authorization::Revoked => {
                self.update_metrics(|metrics| {
                    metrics.revoked_capabilities = metrics.revoked_capabilities.saturating_add(1);
                });
                return Ok(());
            }
            Authorization::Full => {
                self.update_metrics(|metrics| {
                    metrics.rate_limited_requests = metrics.rate_limited_requests.saturating_add(1);
                });
                return Ok(());
            }
        }
        let destination = self.destination_digest(&payload)?;
        let collapse_id = destination[..16]
            .try_into()
            .expect("destination digest is fixed");
        let dispatch = {
            let mut runtime = self.lock_runtime();
            if !allow_window(
                &mut runtime.capability,
                payload.capability_id,
                self.limits.max_capability_buckets,
                self.limits.per_capability_per_minute,
                now,
            ) || !allow_window(
                &mut runtime.destination,
                destination,
                self.limits.max_destination_buckets,
                self.limits.per_destination_per_minute,
                now,
            ) || !allow_global(&mut runtime.global, self.limits.global_per_minute, now)
            {
                self.update_metrics(|metrics| {
                    metrics.rate_limited_requests = metrics.rate_limited_requests.saturating_add(1);
                });
                false
            } else if runtime
                .coalesced_until
                .get(&destination)
                .is_some_and(|deadline| *deadline > now)
            {
                self.update_metrics(|metrics| {
                    metrics.coalesced_requests = metrics.coalesced_requests.saturating_add(1);
                });
                false
            } else {
                prune_coalescing(
                    &mut runtime.coalesced_until,
                    now,
                    self.limits.max_destination_buckets,
                );
                if runtime.coalesced_until.len() >= self.limits.max_destination_buckets
                    && !runtime.coalesced_until.contains_key(&destination)
                {
                    self.update_metrics(|metrics| {
                        metrics.rate_limited_requests =
                            metrics.rate_limited_requests.saturating_add(1);
                    });
                    false
                } else {
                    runtime.coalesced_until.insert(
                        destination,
                        now.saturating_add(self.limits.coalesce_seconds),
                    );
                    true
                }
            }
        };
        if !dispatch {
            return Ok(());
        }
        let native = NativePushRequest::new(
            payload.platform,
            payload.environment,
            payload.profile,
            payload.provider_token,
            payload.app_topic,
            collapse_id,
        );
        match tokio::time::timeout(self.limits.provider_timeout, self.provider.send(native)).await {
            Ok(Ok(())) => {
                self.update_metrics(|metrics| {
                    metrics.provider_successes = metrics.provider_successes.saturating_add(1);
                });
            }
            Ok(Err(error)) => {
                self.record_provider_error(error);
                if error == ProviderErrorClass::InvalidDestination {
                    let _ =
                        self.lock_durable()
                            .revoke(&payload.capability_id, payload.expires_at, now);
                }
            }
            Err(_) => {
                self.record_provider_error(ProviderErrorClass::Unavailable);
            }
        }
        Ok(())
    }

    /// Process one possession-authorized revocation and return the generic body.
    pub fn revoke(&self, body: &[u8], now: u64) -> [u8; WAKE_GENERIC_RESPONSE_LEN] {
        let _ = self.try_revoke(body, now);
        wake_generic_response()
    }

    fn try_revoke(&self, body: &[u8], now: u64) -> Result<()> {
        let request = match WakeTriggerRequest::decode(body) {
            Ok(request) => request,
            Err(_) => {
                self.update_metrics(|metrics| {
                    metrics.malformed_requests = metrics.malformed_requests.saturating_add(1);
                });
                return Err(WakeError::Invalid("wake revoke body"));
            }
        };
        let payload = match self.open_capability(&request.capability) {
            Ok(payload) => payload,
            Err(error) => {
                self.update_metrics(|metrics| {
                    metrics.invalid_capabilities = metrics.invalid_capabilities.saturating_add(1);
                });
                return Err(error);
            }
        };
        if payload.expires_at <= now
            || payload.expires_at.saturating_sub(now) > WAKE_CAPABILITY_MAX_LIFETIME_SECS
        {
            self.update_metrics(|metrics| {
                metrics.expired_capabilities = metrics.expired_capabilities.saturating_add(1);
            });
            return Ok(());
        }
        if self
            .lock_durable()
            .revoke(&payload.capability_id, payload.expires_at, now)?
        {
            self.update_metrics(|metrics| {
                metrics.capabilities_revoked = metrics.capabilities_revoked.saturating_add(1);
            });
        } else {
            self.update_metrics(|metrics| {
                metrics.rate_limited_requests = metrics.rate_limited_requests.saturating_add(1);
            });
        }
        Ok(())
    }

    fn open_capability(&self, capability: &WakeCapability) -> Result<WakeCapabilityPayload> {
        let plaintext = self.keys.open(
            capability.key_id(),
            &capability.nonce(),
            capability.sealed_payload(),
            WAKE_CAPABILITY_ASSOCIATED_DATA,
        )?;
        if plaintext.len() != WAKE_CAPABILITY_PLAINTEXT_LEN {
            return Err(WakeError::Key);
        }
        WakeCapabilityPayload::decode(&plaintext)
            .map_err(|_| WakeError::Invalid("wake capability plaintext"))
    }

    fn destination_digest(&self, payload: &WakeCapabilityPayload) -> Result<[u8; 32]> {
        let mut mac =
            HmacSha256::new_from_slice(&self.destination_secret).map_err(|_| WakeError::Key)?;
        mac.update(b"Komms-Wake-Destination-v1");
        mac.update(&[
            payload.platform as u8,
            payload.environment as u8,
            payload.profile as u8,
        ]);
        mac.update(
            &u16::try_from(payload.provider_token.len())
                .map_err(|_| WakeError::Invalid("wake token length"))?
                .to_be_bytes(),
        );
        mac.update(&payload.provider_token);
        mac.update(
            &u16::try_from(payload.app_topic.len())
                .map_err(|_| WakeError::Invalid("wake topic length"))?
                .to_be_bytes(),
        );
        mac.update(&payload.app_topic);
        Ok(mac.finalize().into_bytes().into())
    }

    fn record_provider_error(&self, error: ProviderErrorClass) {
        let mut metrics = self.lock_metrics();
        let counter = match error {
            ProviderErrorClass::Unavailable => &mut metrics.provider_unavailable,
            ProviderErrorClass::RateLimited => &mut metrics.provider_rate_limited,
            ProviderErrorClass::Authentication => &mut metrics.provider_authentication,
            ProviderErrorClass::InvalidDestination => &mut metrics.provider_invalid_destination,
            ProviderErrorClass::Other => &mut metrics.provider_other,
        };
        *counter = counter.saturating_add(1);
    }

    fn update_metrics(&self, update: impl FnOnce(&mut GatewayMetrics)) {
        let mut metrics = self.lock_metrics();
        update(&mut metrics);
    }

    /// Snapshot content-free aggregate metrics.
    pub fn metrics(&self) -> GatewayMetrics {
        *self.lock_metrics()
    }

    /// Purge expired durable rows and return only aggregate live counts.
    pub fn state_counts(&self, now: u64) -> Result<GatewayStateCounts> {
        self.lock_durable().counts(now)
    }

    fn lock_durable(&self) -> MutexGuard<'_, GatewayStateStore> {
        self.durable
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock_runtime(&self) -> MutexGuard<'_, RuntimeState> {
        self.runtime
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn lock_metrics(&self) -> MutexGuard<'_, GatewayMetrics> {
        self.metrics
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Drop for WakeGateway {
    fn drop(&mut self) {
        self.destination_secret.zeroize();
    }
}

fn allow_window<const N: usize>(
    windows: &mut HashMap<[u8; N], Window>,
    key: [u8; N],
    max_buckets: usize,
    limit: u32,
    now: u64,
) -> bool {
    let minute = now / 60;
    windows.retain(|_, window| window.minute.saturating_add(1) >= minute);
    if !windows.contains_key(&key) && windows.len() >= max_buckets {
        return false;
    }
    let window = windows.entry(key).or_insert(Window { minute, count: 0 });
    if window.minute != minute {
        *window = Window { minute, count: 0 };
    }
    if window.count >= limit {
        return false;
    }
    window.count = window.count.saturating_add(1);
    true
}

fn allow_global(window: &mut Option<Window>, limit: u32, now: u64) -> bool {
    let minute = now / 60;
    let current = window.get_or_insert(Window { minute, count: 0 });
    if current.minute != minute {
        *current = Window { minute, count: 0 };
    }
    if current.count >= limit {
        return false;
    }
    current.count = current.count.saturating_add(1);
    true
}

fn prune_coalescing(windows: &mut HashMap<[u8; 32], u64>, now: u64, max: usize) {
    windows.retain(|_, deadline| *deadline > now);
    if windows.len() <= max {
        return;
    }
    let mut entries = windows
        .iter()
        .map(|(destination, deadline)| (*destination, *deadline))
        .collect::<Vec<_>>();
    entries.sort_by_key(|(_, deadline)| *deadline);
    for (destination, _) in entries.into_iter().take(windows.len() - max) {
        windows.remove(&destination);
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use rand::{rngs::StdRng, SeedableRng};

    use kult_protocol::{
        verify_wake_generic_response, WakeEnvironment, WakePlatform, WakeProfile,
        WakeRegisterRequest, WakeRegisterResponse, WakeTriggerRequest,
    };

    use crate::{
        generate_capability_key, FileCapabilityKeyring, GatewayStateStore, NativePushProvider,
    };

    use super::*;

    const NOW: u64 = 1_800_000_000;
    type RecordedPush = (Vec<u8>, Vec<u8>, Vec<u8>, bool);

    #[derive(Default)]
    struct RecordingProvider {
        requests: Mutex<Vec<RecordedPush>>,
        error: Mutex<Option<ProviderErrorClass>>,
    }

    #[async_trait]
    impl NativePushProvider for RecordingProvider {
        async fn send(
            &self,
            request: NativePushRequest,
        ) -> core::result::Result<(), ProviderErrorClass> {
            self.requests.lock().unwrap().push((
                request.provider_token().to_vec(),
                request.app_topic().to_vec(),
                request.payload().to_vec(),
                request.fcm_high_priority(),
            ));
            match *self.error.lock().unwrap() {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
    }

    struct BlackholeProvider;

    #[async_trait]
    impl NativePushProvider for BlackholeProvider {
        async fn send(
            &self,
            _request: NativePushRequest,
        ) -> core::result::Result<(), ProviderErrorClass> {
            std::future::pending().await
        }
    }

    fn gateway(
        directory: &Path,
        provider: Arc<RecordingProvider>,
        limits: GatewayLimits,
        seed: u64,
    ) -> WakeGateway {
        let key = directory.join(format!("{seed}.key"));
        let state = directory.join(format!("{seed}.db"));
        let mut rng = StdRng::seed_from_u64(seed);
        generate_capability_key(&key, seed as u32, NOW - 1, &mut rng).unwrap();
        let keys = Arc::new(FileCapabilityKeyring::open(seed as u32, &[key]).unwrap());
        let state = GatewayStateStore::open(&state, 128, 128).unwrap();
        WakeGateway::new(keys, state, provider, limits, &mut rng).unwrap()
    }

    fn issue(
        gateway: &WakeGateway,
        token: &[u8],
        nonce: [u8; 16],
        seed: u64,
    ) -> WakeRegisterResponse {
        let request = WakeRegisterRequest {
            platform: WakePlatform::Fcm,
            environment: WakeEnvironment::Production,
            profile: WakeProfile::GenericVisible,
            provider_token: token.to_vec(),
            app_topic: b"is.komms.android".to_vec(),
            request_nonce: nonce,
        };
        let mut rng = StdRng::seed_from_u64(seed);
        WakeRegisterResponse::decode(&gateway.register(&request.encode().unwrap(), NOW, &mut rng))
            .unwrap()
    }

    #[tokio::test]
    async fn trigger_is_static_replay_bounded_and_destination_coalesced() {
        let directory = tempfile::tempdir().unwrap();
        let provider = Arc::new(RecordingProvider::default());
        let gateway = gateway(
            directory.path(),
            provider.clone(),
            GatewayLimits::default(),
            1,
        );
        let first = issue(&gateway, b"same-destination", [1u8; 16], 11);
        let second = issue(&gateway, b"same-destination", [2u8; 16], 12);
        let first_trigger = WakeTriggerRequest {
            capability: first.capability.unwrap(),
            request_nonce: [3u8; 16],
        }
        .encode()
        .unwrap();
        let second_trigger = WakeTriggerRequest {
            capability: second.capability.unwrap(),
            request_nonce: [4u8; 16],
        }
        .encode()
        .unwrap();
        verify_wake_generic_response(&gateway.trigger(&first_trigger, NOW + 1).await).unwrap();
        verify_wake_generic_response(&gateway.trigger(&first_trigger, NOW + 1).await).unwrap();
        verify_wake_generic_response(&gateway.trigger(&second_trigger, NOW + 1).await).unwrap();
        let requests = provider.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0, b"same-destination");
        assert_eq!(requests[0].1, b"is.komms.android");
        assert_eq!(requests[0].2, crate::FCM_GENERIC_PAYLOAD);
        assert!(requests[0].3);
        let metrics = gateway.metrics();
        assert_eq!(metrics.provider_successes, 1);
        assert_eq!(metrics.replayed_requests, 1);
        assert_eq!(metrics.coalesced_requests, 1);
    }

    #[tokio::test]
    async fn revoke_expiry_malformed_and_provider_error_are_generic() {
        let directory = tempfile::tempdir().unwrap();
        let provider = Arc::new(RecordingProvider::default());
        let gateway = gateway(
            directory.path(),
            provider.clone(),
            GatewayLimits {
                capability_lifetime_secs: 10,
                coalesce_seconds: 1,
                ..GatewayLimits::default()
            },
            2,
        );
        let issued = issue(&gateway, b"token", [1u8; 16], 21);
        let capability = issued.capability.unwrap();
        let revoke = WakeTriggerRequest {
            capability: capability.clone(),
            request_nonce: [2u8; 16],
        }
        .encode()
        .unwrap();
        verify_wake_generic_response(&gateway.revoke(&revoke, NOW + 1)).unwrap();
        let trigger = WakeTriggerRequest {
            capability: capability.clone(),
            request_nonce: [3u8; 16],
        }
        .encode()
        .unwrap();
        verify_wake_generic_response(&gateway.trigger(&trigger, NOW + 2).await).unwrap();
        let expired = WakeTriggerRequest {
            capability,
            request_nonce: [4u8; 16],
        }
        .encode()
        .unwrap();
        verify_wake_generic_response(&gateway.trigger(&expired, NOW + 11).await).unwrap();
        verify_wake_generic_response(&gateway.trigger(&[1u8; 8], NOW + 1).await).unwrap();
        assert!(provider.requests.lock().unwrap().is_empty());
        let metrics = gateway.metrics();
        assert_eq!(metrics.capabilities_revoked, 1);
        assert_eq!(metrics.revoked_capabilities, 1);
        assert_eq!(metrics.expired_capabilities, 1);
        assert_eq!(metrics.malformed_requests, 1);
    }

    #[tokio::test]
    async fn invalid_destination_is_reduced_and_retires_capability() {
        let directory = tempfile::tempdir().unwrap();
        let provider = Arc::new(RecordingProvider::default());
        *provider.error.lock().unwrap() = Some(ProviderErrorClass::InvalidDestination);
        let gateway = gateway(
            directory.path(),
            provider.clone(),
            GatewayLimits {
                coalesce_seconds: 1,
                ..GatewayLimits::default()
            },
            3,
        );
        let issued = issue(&gateway, b"invalid", [1u8; 16], 31);
        let capability = issued.capability.unwrap();
        for nonce in [[2u8; 16], [3u8; 16]] {
            let trigger = WakeTriggerRequest {
                capability: capability.clone(),
                request_nonce: nonce,
            }
            .encode()
            .unwrap();
            gateway.trigger(&trigger, NOW + u64::from(nonce[0])).await;
        }
        assert_eq!(provider.requests.lock().unwrap().len(), 1);
        assert_eq!(gateway.metrics().provider_invalid_destination, 1);
        assert_eq!(gateway.metrics().revoked_capabilities, 1);
    }

    #[tokio::test]
    async fn prior_capability_key_and_revocation_survive_gateway_restart() {
        let directory = tempfile::tempdir().unwrap();
        let first_key = directory.path().join("first.key");
        let second_key = directory.path().join("second.key");
        let state_path = directory.path().join("restart.db");
        let mut rng = StdRng::seed_from_u64(81);
        generate_capability_key(&first_key, 1, NOW - 200, &mut rng).unwrap();
        generate_capability_key(&second_key, 2, NOW - 100, &mut rng).unwrap();
        let provider = Arc::new(RecordingProvider::default());

        let first_gateway = WakeGateway::new(
            Arc::new(FileCapabilityKeyring::open(1, std::slice::from_ref(&first_key)).unwrap()),
            GatewayStateStore::open(&state_path, 128, 128).unwrap(),
            provider.clone(),
            GatewayLimits::default(),
            &mut rng,
        )
        .unwrap();
        let issued = issue(&first_gateway, b"restart-token", [1u8; 16], 82);
        let capability = issued.capability.unwrap();
        assert_eq!(capability.key_id(), 1);
        drop(first_gateway);

        let rotated_gateway = WakeGateway::new(
            Arc::new(
                FileCapabilityKeyring::open(2, &[first_key.clone(), second_key.clone()]).unwrap(),
            ),
            GatewayStateStore::open(&state_path, 128, 128).unwrap(),
            provider.clone(),
            GatewayLimits::default(),
            &mut rng,
        )
        .unwrap();
        let trigger = WakeTriggerRequest {
            capability: capability.clone(),
            request_nonce: [2u8; 16],
        }
        .encode()
        .unwrap();
        verify_wake_generic_response(&rotated_gateway.trigger(&trigger, NOW + 1).await).unwrap();
        assert_eq!(provider.requests.lock().unwrap().len(), 1);
        let revoke = WakeTriggerRequest {
            capability: capability.clone(),
            request_nonce: [3u8; 16],
        }
        .encode()
        .unwrap();
        verify_wake_generic_response(&rotated_gateway.revoke(&revoke, NOW + 2)).unwrap();
        let next = issue(&rotated_gateway, b"next-token", [4u8; 16], 83);
        assert_eq!(next.capability.unwrap().key_id(), 2);
        drop(rotated_gateway);

        let restarted_gateway = WakeGateway::new(
            Arc::new(FileCapabilityKeyring::open(2, &[first_key, second_key]).unwrap()),
            GatewayStateStore::open(&state_path, 128, 128).unwrap(),
            provider.clone(),
            GatewayLimits::default(),
            &mut rng,
        )
        .unwrap();
        let after_restart = WakeTriggerRequest {
            capability,
            request_nonce: [5u8; 16],
        }
        .encode()
        .unwrap();
        verify_wake_generic_response(&restarted_gateway.trigger(&after_restart, NOW + 3).await)
            .unwrap();
        assert_eq!(provider.requests.lock().unwrap().len(), 1);
        assert_eq!(restarted_gateway.metrics().revoked_capabilities, 1);
    }

    #[tokio::test]
    async fn provider_outage_is_generic_and_later_work_can_retry() {
        let directory = tempfile::tempdir().unwrap();
        let provider = Arc::new(RecordingProvider::default());
        let gateway = gateway(
            directory.path(),
            Arc::clone(&provider),
            GatewayLimits::default(),
            9,
        );
        let issued = issue(&gateway, b"outage-token", [1u8; 16], 91);
        let capability = issued.capability.unwrap();
        *provider.error.lock().unwrap() = Some(ProviderErrorClass::Unavailable);
        let first = WakeTriggerRequest {
            capability: capability.clone(),
            request_nonce: [2u8; 16],
        }
        .encode()
        .unwrap();
        let response = gateway.trigger(&first, NOW + 1).await;
        assert_eq!(response, wake_generic_response());
        assert_eq!(gateway.metrics().provider_unavailable, 1);

        *provider.error.lock().unwrap() = None;
        let retry = WakeTriggerRequest {
            capability,
            request_nonce: [3u8; 16],
        }
        .encode()
        .unwrap();
        let response = gateway.trigger(&retry, NOW + 32).await;
        assert_eq!(response, wake_generic_response());
        assert_eq!(provider.requests.lock().unwrap().len(), 2);
        assert_eq!(gateway.metrics().provider_successes, 1);
    }

    #[tokio::test]
    async fn provider_blackhole_is_deadline_bounded_and_generic() {
        let directory = tempfile::tempdir().unwrap();
        let key = directory.path().join("blackhole.key");
        let state = directory.path().join("blackhole.db");
        let mut rng = StdRng::seed_from_u64(101);
        generate_capability_key(&key, 1, NOW - 1, &mut rng).unwrap();
        let gateway = WakeGateway::new(
            Arc::new(FileCapabilityKeyring::open(1, &[key]).unwrap()),
            GatewayStateStore::open(&state, 128, 128).unwrap(),
            Arc::new(BlackholeProvider),
            GatewayLimits {
                provider_timeout: Duration::from_millis(10),
                ..GatewayLimits::default()
            },
            &mut rng,
        )
        .unwrap();
        let issued = issue(&gateway, b"blackhole-token", [1u8; 16], 102);
        let trigger = WakeTriggerRequest {
            capability: issued.capability.unwrap(),
            request_nonce: [2u8; 16],
        }
        .encode()
        .unwrap();
        let response =
            tokio::time::timeout(Duration::from_secs(1), gateway.trigger(&trigger, NOW + 1))
                .await
                .unwrap();
        assert_eq!(response, wake_generic_response());
        assert_eq!(gateway.metrics().provider_unavailable, 1);
        assert_eq!(gateway.metrics().provider_successes, 0);
    }
}
