//! Least-authority ADR-0018 rendezvous service component.
//!
//! This crate owns no Komms user identity, mailbox, message, prekey, contact,
//! notification or delivery state. It retains fixed-width opaque records in
//! process memory for at most two hours and returns fixed-shape hit/miss
//! responses. Network/TLS termination is supplied by the dedicated reference
//! service binary, never by the identity-bearing endpoint daemon.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use rand_core::CryptoRngCore;
use zeroize::Zeroize;

use kult_crypto::{rendezvous_epoch, RENDEZVOUS_MAX_TTL_SECS, RENDEZVOUS_SEALED_RECORD_LEN};
use kult_protocol::{
    RendezvousLookupRequest, RendezvousRegisterRequest, RENDEZVOUS_LOOKUP_PATH,
    RENDEZVOUS_LOOKUP_RESPONSE_LEN, RENDEZVOUS_MALFORMED_RESPONSE_LEN, RENDEZVOUS_MEDIA_TYPE,
    RENDEZVOUS_REGISTER_ACK_LEN, RENDEZVOUS_REGISTER_PATH,
};

/// One minute rate-accounting window.
pub const RATE_WINDOW_SECS: u64 = 60;
/// Maximum expired rows swept by one request.
pub const MAX_EXPIRY_SWEEP_PER_REQUEST: usize = 64;
/// Conservative fixed accounting per retained row, including map overhead.
pub const ACCOUNTED_BYTES_PER_RECORD: usize = RENDEZVOUS_SEALED_RECORD_LEN + 32 + 8 + 8 + 128;
/// Conservative accounting for one opaque per-slot rate bucket.
pub const ACCOUNTED_BYTES_PER_SLOT_BUCKET: usize = 128;
/// Conservative accounting for one coarse ephemeral client-rate bucket.
pub const ACCOUNTED_BYTES_PER_CLIENT_BUCKET: usize = 128;

/// Bounded service policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RendezvousServiceConfig {
    /// Maximum live slot rows.
    pub max_records: usize,
    /// Maximum accounted mutable bytes.
    pub max_memory_bytes: usize,
    /// Maximum simultaneous request handlers.
    pub max_concurrent_requests: usize,
    /// Maximum accepted operations in one minute.
    pub max_global_operations_per_minute: u32,
    /// Maximum fixed request/response bytes in one minute.
    pub max_global_bytes_per_minute: u64,
    /// Maximum operations per opaque slot in one minute.
    pub max_slot_operations_per_minute: u32,
    /// Maximum live opaque slot-rate buckets in one minute.
    pub max_slot_buckets: usize,
    /// Maximum operations per ingress-derived client bucket in one minute.
    pub max_client_operations_per_minute: u32,
    /// Maximum live client rate buckets.
    pub max_client_buckets: usize,
}

impl Default for RendezvousServiceConfig {
    fn default() -> Self {
        Self {
            max_records: 16_384,
            max_memory_bytes: 96 * 1024 * 1024,
            max_concurrent_requests: 256,
            max_global_operations_per_minute: 120_000,
            max_global_bytes_per_minute: 512 * 1024 * 1024,
            max_slot_operations_per_minute: 24,
            max_slot_buckets: 65_536,
            max_client_operations_per_minute: 600,
            max_client_buckets: 16_384,
        }
    }
}

impl RendezvousServiceConfig {
    fn valid(self) -> bool {
        let accounted = self
            .max_records
            .checked_mul(ACCOUNTED_BYTES_PER_RECORD)
            .and_then(|bytes| {
                self.max_slot_buckets
                    .checked_mul(ACCOUNTED_BYTES_PER_SLOT_BUCKET)
                    .and_then(|slots| bytes.checked_add(slots))
            })
            .and_then(|bytes| {
                self.max_client_buckets
                    .checked_mul(ACCOUNTED_BYTES_PER_CLIENT_BUCKET)
                    .and_then(|clients| bytes.checked_add(clients))
            });
        self.max_records > 0
            && self.max_concurrent_requests > 0
            && self.max_global_operations_per_minute > 0
            && self.max_global_bytes_per_minute > 0
            && self.max_slot_operations_per_minute > 0
            && self.max_slot_buckets > 0
            && self.max_client_operations_per_minute > 0
            && self.max_client_buckets > 0
            && accounted.is_some_and(|bytes| bytes <= self.max_memory_bytes)
    }
}

/// Coarse ephemeral ingress bucket supplied by the network boundary.
///
/// A direct ingress may derive this from a short-lived keyed address prefix;
/// an anonymized ingress uses an anonymous admission bucket. It is never
/// logged or returned and expires from memory after its rate window.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ClientAdmissionKey(pub [u8; 16]);

/// Fixed-shape HTTP result produced without request identifiers or logging.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceResponse {
    /// HTTP status (`200` for every syntactically valid operation, `400` for
    /// malformed path/media-type/body).
    pub status: u16,
    /// Exact fixed-width binary body.
    pub body: Vec<u8>,
    /// Always the normative binary media type.
    pub media_type: &'static str,
    /// Always true; a network wrapper must emit `Cache-Control: no-store`.
    pub no_store: bool,
}

impl ServiceResponse {
    fn ok(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            body,
            media_type: RENDEZVOUS_MEDIA_TYPE,
            no_store: true,
        }
    }

    fn malformed(rng: &mut impl CryptoRngCore) -> Self {
        let mut body = vec![0u8; RENDEZVOUS_MALFORMED_RESPONSE_LEN];
        rng.fill_bytes(&mut body);
        Self {
            status: 400,
            body,
            media_type: RENDEZVOUS_MEDIA_TYPE,
            no_store: true,
        }
    }
}

#[derive(Clone)]
struct StoredRecord {
    epoch: u64,
    expires_at: u64,
    sealed: [u8; RENDEZVOUS_SEALED_RECORD_LEN],
}

impl Drop for StoredRecord {
    fn drop(&mut self) {
        self.sealed.zeroize();
    }
}

#[derive(Clone, Copy, Default)]
struct RateBucket {
    window: u64,
    operations: u32,
    bytes: u64,
}

impl RateBucket {
    fn charge(&mut self, now: u64, operations: u32, bytes: u64) {
        let window = now / RATE_WINDOW_SECS;
        if self.window != window {
            *self = Self {
                window,
                operations: 0,
                bytes: 0,
            };
        }
        self.operations = self.operations.saturating_add(operations);
        self.bytes = self.bytes.saturating_add(bytes);
    }
}

#[derive(Default)]
struct MutableState {
    records: HashMap<[u8; 32], StoredRecord>,
    slot_rates: HashMap<[u8; 32], RateBucket>,
    client_rates: HashMap<ClientAdmissionKey, RateBucket>,
    global_rate: RateBucket,
}

/// In-memory, persistence-free rendezvous service.
pub struct RendezvousService {
    config: RendezvousServiceConfig,
    mutable: Mutex<MutableState>,
    active_requests: AtomicUsize,
}

impl Drop for RendezvousService {
    fn drop(&mut self) {
        let Ok(state) = self.mutable.get_mut() else {
            return;
        };
        for (mut slot, record) in state.records.drain() {
            slot.zeroize();
            drop(record);
        }
        for (mut slot, _) in state.slot_rates.drain() {
            slot.zeroize();
        }
        for (mut client, _) in state.client_rates.drain() {
            client.0.zeroize();
        }
        state.global_rate = RateBucket::default();
    }
}

impl RendezvousService {
    /// Construct a service only when every capacity axis is explicit and
    /// internally consistent.
    pub fn new(config: RendezvousServiceConfig) -> Option<Self> {
        config.valid().then(|| Self {
            config,
            mutable: Mutex::new(MutableState::default()),
            active_requests: AtomicUsize::new(0),
        })
    }

    /// Handle one fixed binary operation.
    ///
    /// The wrapper must reject compression, redirects, cookies,
    /// authentication headers and request-id reflection. This component
    /// enforces exact path, media type and body shape before retaining data.
    pub fn handle(
        &self,
        path: &str,
        media_type: &str,
        body: &[u8],
        client: ClientAdmissionKey,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> ServiceResponse {
        if media_type != RENDEZVOUS_MEDIA_TYPE {
            return ServiceResponse::malformed(rng);
        }
        match path {
            RENDEZVOUS_REGISTER_PATH => {
                let Ok(request) = RendezvousRegisterRequest::decode(body) else {
                    return ServiceResponse::malformed(rng);
                };
                let _active = self.try_enter();
                let admitted = _active.is_some()
                    && self.admit(
                        client,
                        request.slot,
                        body.len() + RENDEZVOUS_REGISTER_ACK_LEN,
                        now,
                    );
                if admitted {
                    self.register(request, now);
                }
                let mut ack = vec![0u8; RENDEZVOUS_REGISTER_ACK_LEN];
                rng.fill_bytes(&mut ack);
                ServiceResponse::ok(ack)
            }
            RENDEZVOUS_LOOKUP_PATH => {
                let Ok(request) = RendezvousLookupRequest::decode(body) else {
                    return ServiceResponse::malformed(rng);
                };
                let _active = self.try_enter();
                let admitted = _active.is_some()
                    && self.admit(
                        client,
                        request.slot,
                        body.len() + RENDEZVOUS_LOOKUP_RESPONSE_LEN,
                        now,
                    );
                let record = admitted
                    .then(|| self.lookup(request, now))
                    .flatten()
                    .map(|record| record.to_vec())
                    .unwrap_or_else(|| {
                        let mut miss = vec![0u8; RENDEZVOUS_LOOKUP_RESPONSE_LEN];
                        rng.fill_bytes(&mut miss);
                        miss
                    });
                ServiceResponse::ok(record)
            }
            _ => ServiceResponse::malformed(rng),
        }
    }

    /// Current retained row count for aggregate health metrics.
    pub fn record_count(&self) -> usize {
        self.mutable
            .lock()
            .map_or(self.config.max_records, |state| state.records.len())
    }

    /// Conservatively accounted mutable record bytes for aggregate metrics.
    pub fn accounted_record_bytes(&self) -> usize {
        self.record_count()
            .saturating_mul(ACCOUNTED_BYTES_PER_RECORD)
    }

    /// Conservative total mutable-state accounting for aggregate health
    /// metrics. No slots, admission buckets, or ciphertext values are exposed.
    pub fn accounted_mutable_bytes(&self) -> usize {
        self.mutable
            .lock()
            .map_or(self.config.max_memory_bytes, |state| {
                state
                    .records
                    .len()
                    .saturating_mul(ACCOUNTED_BYTES_PER_RECORD)
                    .saturating_add(
                        state
                            .slot_rates
                            .len()
                            .saturating_mul(ACCOUNTED_BYTES_PER_SLOT_BUCKET),
                    )
                    .saturating_add(
                        state
                            .client_rates
                            .len()
                            .saturating_mul(ACCOUNTED_BYTES_PER_CLIENT_BUCKET),
                    )
            })
    }

    fn try_enter(&self) -> Option<ActiveRequest<'_>> {
        self.active_requests
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.config.max_concurrent_requests).then_some(active + 1)
            })
            .ok()
            .map(|_| ActiveRequest {
                count: &self.active_requests,
            })
    }

    fn admit(&self, client: ClientAdmissionKey, slot: [u8; 32], bytes: usize, now: u64) -> bool {
        let Ok(mut state) = self.mutable.lock() else {
            return false;
        };
        Self::sweep_expired(&mut state, now);
        let window = now / RATE_WINDOW_SECS;
        state.slot_rates.retain(|_, bucket| bucket.window == window);
        state
            .client_rates
            .retain(|_, bucket| bucket.window == window);
        if !state.client_rates.contains_key(&client)
            && state.client_rates.len() >= self.config.max_client_buckets
        {
            return false;
        }
        if !state.slot_rates.contains_key(&slot)
            && state.slot_rates.len() >= self.config.max_slot_buckets
        {
            return false;
        }
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        let global = state.global_rate;
        let slot_rate = state.slot_rates.get(&slot).copied().unwrap_or_default();
        let client_rate = state.client_rates.get(&client).copied().unwrap_or_default();
        let current_global_ops = if global.window == window {
            global.operations
        } else {
            0
        };
        let current_global_bytes = if global.window == window {
            global.bytes
        } else {
            0
        };
        let current_slot_ops = if slot_rate.window == window {
            slot_rate.operations
        } else {
            0
        };
        let current_client_ops = if client_rate.window == window {
            client_rate.operations
        } else {
            0
        };
        if current_global_ops >= self.config.max_global_operations_per_minute
            || current_global_bytes.saturating_add(bytes) > self.config.max_global_bytes_per_minute
            || current_slot_ops >= self.config.max_slot_operations_per_minute
            || current_client_ops >= self.config.max_client_operations_per_minute
        {
            return false;
        }
        state.global_rate.charge(now, 1, bytes);
        state.slot_rates.entry(slot).or_default().charge(now, 1, 0);
        state
            .client_rates
            .entry(client)
            .or_default()
            .charge(now, 1, 0);
        true
    }

    fn register(&self, request: RendezvousRegisterRequest, now: u64) {
        let epoch = rendezvous_epoch(now);
        if request.epoch != epoch && request.epoch != epoch.saturating_add(1) {
            return;
        }
        let Ok(mut state) = self.mutable.lock() else {
            return;
        };
        Self::sweep_expired(&mut state, now);
        let replacing = state.records.contains_key(&request.slot);
        if !replacing
            && (state.records.len() >= self.config.max_records
                || state
                    .records
                    .len()
                    .saturating_add(1)
                    .saturating_mul(ACCOUNTED_BYTES_PER_RECORD)
                    > self.config.max_memory_bytes)
        {
            return;
        }
        state.records.insert(
            request.slot,
            StoredRecord {
                epoch: request.epoch,
                expires_at: now
                    .saturating_add(u64::from(request.ttl_seconds.min(RENDEZVOUS_MAX_TTL_SECS))),
                sealed: request.sealed_record,
            },
        );
    }

    fn lookup(
        &self,
        request: RendezvousLookupRequest,
        now: u64,
    ) -> Option<[u8; RENDEZVOUS_SEALED_RECORD_LEN]> {
        let current = rendezvous_epoch(now);
        if request.epoch < current.saturating_sub(1) || request.epoch > current.saturating_add(1) {
            return None;
        }
        let mut state = self.mutable.lock().ok()?;
        Self::sweep_expired(&mut state, now);
        state
            .records
            .get(&request.slot)
            .filter(|record| record.epoch == request.epoch && record.expires_at > now)
            .map(|record| record.sealed)
    }

    fn sweep_expired(state: &mut MutableState, now: u64) {
        let expired = state
            .records
            .iter()
            .filter_map(|(slot, record)| (record.expires_at <= now).then_some(*slot))
            .take(MAX_EXPIRY_SWEEP_PER_REQUEST)
            .collect::<Vec<_>>();
        for slot in expired {
            state.records.remove(&slot);
            state.slot_rates.remove(&slot);
        }
    }
}

struct ActiveRequest<'a> {
    count: &'a AtomicUsize,
}

impl Drop for ActiveRequest<'_> {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, RngCore, SeedableRng};

    use super::*;

    fn config() -> RendezvousServiceConfig {
        RendezvousServiceConfig {
            max_records: 2,
            max_concurrent_requests: 1,
            max_global_operations_per_minute: 32,
            max_global_bytes_per_minute: 1_000_000,
            max_slot_operations_per_minute: 8,
            max_slot_buckets: 4,
            max_client_operations_per_minute: 16,
            max_client_buckets: 4,
            max_memory_bytes: 2 * ACCOUNTED_BYTES_PER_RECORD
                + 4 * ACCOUNTED_BYTES_PER_SLOT_BUCKET
                + 4 * ACCOUNTED_BYTES_PER_CLIENT_BUCKET,
        }
    }

    fn register(slot: [u8; 32], epoch: u64, sealed: [u8; RENDEZVOUS_SEALED_RECORD_LEN]) -> Vec<u8> {
        RendezvousRegisterRequest {
            slot,
            epoch,
            ttl_seconds: 7_200,
            sealed_record: sealed,
        }
        .encode()
        .unwrap()
        .to_vec()
    }

    fn lookup(slot: [u8; 32], epoch: u64) -> Vec<u8> {
        RendezvousLookupRequest { slot, epoch }.encode().to_vec()
    }

    #[test]
    fn accepted_only_by_subsequent_lookup_and_hit_miss_shapes_match() {
        let service = RendezvousService::new(config()).unwrap();
        let mut rng = StdRng::seed_from_u64(1);
        let now = 10 * 3_600;
        let epoch = rendezvous_epoch(now);
        let sealed = [9u8; RENDEZVOUS_SEALED_RECORD_LEN];
        let ack = service.handle(
            RENDEZVOUS_REGISTER_PATH,
            RENDEZVOUS_MEDIA_TYPE,
            &register([1u8; 32], epoch, sealed),
            ClientAdmissionKey([2u8; 16]),
            now,
            &mut rng,
        );
        assert_eq!(ack.status, 200);
        assert_eq!(ack.body.len(), RENDEZVOUS_REGISTER_ACK_LEN);

        let hit = service.handle(
            RENDEZVOUS_LOOKUP_PATH,
            RENDEZVOUS_MEDIA_TYPE,
            &lookup([1u8; 32], epoch),
            ClientAdmissionKey([3u8; 16]),
            now,
            &mut rng,
        );
        let miss = service.handle(
            RENDEZVOUS_LOOKUP_PATH,
            RENDEZVOUS_MEDIA_TYPE,
            &lookup([4u8; 32], epoch),
            ClientAdmissionKey([3u8; 16]),
            now,
            &mut rng,
        );
        assert_eq!(hit.body, sealed);
        assert_eq!(hit.status, miss.status);
        assert_eq!(hit.body.len(), miss.body.len());
        assert_ne!(miss.body, sealed);
    }

    #[test]
    fn capacity_rate_concurrency_expiry_and_restart_fail_closed() {
        let service = RendezvousService::new(config()).unwrap();
        let mut rng = StdRng::seed_from_u64(2);
        let now = 20 * 3_600;
        let epoch = rendezvous_epoch(now);
        for value in 1..=3 {
            let mut sealed = [0u8; RENDEZVOUS_SEALED_RECORD_LEN];
            rng.fill_bytes(&mut sealed);
            let response = service.handle(
                RENDEZVOUS_REGISTER_PATH,
                RENDEZVOUS_MEDIA_TYPE,
                &register([value; 32], epoch, sealed),
                ClientAdmissionKey([value; 16]),
                now,
                &mut rng,
            );
            assert_eq!(response.body.len(), RENDEZVOUS_REGISTER_ACK_LEN);
        }
        assert_eq!(service.record_count(), 2);
        assert!(service.accounted_mutable_bytes() <= config().max_memory_bytes);

        let held = service.try_enter().unwrap();
        let overloaded = service.handle(
            RENDEZVOUS_LOOKUP_PATH,
            RENDEZVOUS_MEDIA_TYPE,
            &lookup([1u8; 32], epoch),
            ClientAdmissionKey([1u8; 16]),
            now,
            &mut rng,
        );
        assert_eq!(overloaded.status, 200);
        assert_eq!(overloaded.body.len(), RENDEZVOUS_LOOKUP_RESPONSE_LEN);
        drop(held);

        let expired = service.handle(
            RENDEZVOUS_LOOKUP_PATH,
            RENDEZVOUS_MEDIA_TYPE,
            &lookup([1u8; 32], epoch),
            ClientAdmissionKey([1u8; 16]),
            now + 7_201,
            &mut rng,
        );
        assert_eq!(expired.body.len(), RENDEZVOUS_LOOKUP_RESPONSE_LEN);
        assert_eq!(service.record_count(), 0);

        let restarted = RendezvousService::new(config()).unwrap();
        assert_eq!(restarted.record_count(), 0);
    }

    #[test]
    fn malformed_requests_are_uniform_and_never_allocate_variable_responses() {
        let service = RendezvousService::new(config()).unwrap();
        let mut rng = StdRng::seed_from_u64(3);
        for (path, media, body) in [
            ("/unknown", RENDEZVOUS_MEDIA_TYPE, vec![0u8; 1]),
            (RENDEZVOUS_LOOKUP_PATH, "application/json", vec![0u8; 64]),
            (RENDEZVOUS_LOOKUP_PATH, RENDEZVOUS_MEDIA_TYPE, vec![0u8; 63]),
            (
                RENDEZVOUS_REGISTER_PATH,
                RENDEZVOUS_MEDIA_TYPE,
                vec![0u8; 32],
            ),
        ] {
            let response = service.handle(
                path,
                media,
                &body,
                ClientAdmissionKey([0u8; 16]),
                1,
                &mut rng,
            );
            assert_eq!(response.status, 400);
            assert_eq!(response.body.len(), RENDEZVOUS_MALFORMED_RESPONSE_LEN);
            assert!(response.no_store);
        }
        assert_eq!(service.record_count(), 0);
    }
}
