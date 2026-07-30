//! ADR-0018 fixed-width rendezvous route and HTTP-body codecs.
//!
//! The service handles only [`RendezvousRegisterRequest`] and
//! [`RendezvousLookupRequest`] bytes. Route semantics are authenticated and
//! parsed solely by endpoints after `kult-crypto` opens the sealed record.

use alloc::string::String;
use alloc::vec::Vec;

use kult_crypto::{
    RENDEZVOUS_MAX_TTL_SECS, RENDEZVOUS_RECORD_PLAINTEXT_LEN, RENDEZVOUS_SEALED_RECORD_LEN,
};

use crate::{ProtocolError, Result};

/// Route-record version accepted by stable-v1 rendezvous.
pub const RENDEZVOUS_ROUTE_RECORD_VERSION: u8 = 1;
/// Maximum authenticated routes in one record.
pub const MAX_RENDEZVOUS_ROUTES: usize = 8;
/// Maximum UTF-8 bytes in one route.
pub const MAX_RENDEZVOUS_ROUTE_BYTES: usize = 512;
/// Maximum future issuance skew accepted by an endpoint.
pub const RENDEZVOUS_CLOCK_SKEW_SECS: u64 = 300;
/// Exact register request length.
pub const RENDEZVOUS_REGISTER_REQUEST_LEN: usize = 32 + 8 + 4 + RENDEZVOUS_SEALED_RECORD_LEN;
/// Exact register acknowledgement length.
pub const RENDEZVOUS_REGISTER_ACK_LEN: usize = 64;
/// Exact lookup request length.
pub const RENDEZVOUS_LOOKUP_REQUEST_LEN: usize = 64;
/// Exact lookup response length for both hits and misses.
pub const RENDEZVOUS_LOOKUP_RESPONSE_LEN: usize = RENDEZVOUS_SEALED_RECORD_LEN;
/// Uniform malformed-request response body length.
pub const RENDEZVOUS_MALFORMED_RESPONSE_LEN: usize = 64;
/// Normative HTTP media type.
pub const RENDEZVOUS_MEDIA_TYPE: &str = "application/komms-rendezvous-v1";
/// Register endpoint path.
pub const RENDEZVOUS_REGISTER_PATH: &str = "/v1/rendezvous/register";
/// Lookup endpoint path.
pub const RENDEZVOUS_LOOKUP_PATH: &str = "/v1/rendezvous/lookup";
/// Authenticated pairwise provider-control magic.
pub const RENDEZVOUS_PROVIDER_CONTROL_MAGIC: &[u8; 4] = b"KRV1";
/// Authenticated pairwise provider-control version.
pub const RENDEZVOUS_PROVIDER_CONTROL_VERSION: u8 = 1;
/// Maximum provider descriptors in one authenticated control.
pub const MAX_RENDEZVOUS_CONTROL_PROVIDERS: usize = 8;
/// Maximum canonical provider origin bytes in one control.
pub const MAX_RENDEZVOUS_CONTROL_ORIGIN_BYTES: usize = 512;
/// Maximum complete authenticated provider-control bytes.
pub const MAX_RENDEZVOUS_PROVIDER_CONTROL_BYTES: usize = 4
    + 1
    + 32
    + 32
    + 8
    + 8
    + 1
    + MAX_RENDEZVOUS_CONTROL_PROVIDERS * (2 + MAX_RENDEZVOUS_CONTROL_ORIGIN_BYTES + 32);

const ROUTE_RECORD_HEADER_LEN: usize = 1 + 1 + 8 + 8 + 8 + 8 + 1;
const PROVIDER_CONTROL_HEADER_LEN: usize = 4 + 1 + 32 + 32 + 8 + 8 + 1;

/// One provider descriptor transported only through an authenticated
/// pairwise device session.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RendezvousProviderDescriptor {
    /// Canonical HTTPS origin bytes.
    pub origin: String,
    /// Provider service static key.
    pub static_key: [u8; 32],
}

/// Recipient-selected provider set advertised over a verified device session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RendezvousProviderControl {
    /// Stable sending account.
    pub account: [u8; 32],
    /// Exact sending device session.
    pub device: [u8; 32],
    /// Accepted device-authority generation.
    pub authority_generation: u64,
    /// Strictly increasing provider-set generation.
    pub generation: u64,
    /// Complete sorted provider set; empty explicitly disables rendezvous.
    pub providers: Vec<RendezvousProviderDescriptor>,
}

impl RendezvousProviderControl {
    /// Encode the complete canonical control.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::with_capacity(PROVIDER_CONTROL_HEADER_LEN);
        out.extend_from_slice(RENDEZVOUS_PROVIDER_CONTROL_MAGIC);
        out.push(RENDEZVOUS_PROVIDER_CONTROL_VERSION);
        out.extend_from_slice(&self.account);
        out.extend_from_slice(&self.device);
        out.extend_from_slice(&self.authority_generation.to_be_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.push(u8::try_from(self.providers.len()).map_err(|_| ProtocolError::TooLarge)?);
        for provider in &self.providers {
            let origin = provider.origin.as_bytes();
            out.extend_from_slice(
                &u16::try_from(origin.len())
                    .map_err(|_| ProtocolError::TooLarge)?
                    .to_be_bytes(),
            );
            out.extend_from_slice(origin);
            out.extend_from_slice(&provider.static_key);
        }
        if out.len() > MAX_RENDEZVOUS_PROVIDER_CONTROL_BYTES {
            return Err(ProtocolError::TooLarge);
        }
        Ok(out)
    }

    /// Parse exact canonical provider-control bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < PROVIDER_CONTROL_HEADER_LEN
            || bytes.len() > MAX_RENDEZVOUS_PROVIDER_CONTROL_BYTES
            || &bytes[..4] != RENDEZVOUS_PROVIDER_CONTROL_MAGIC
            || bytes[4] != RENDEZVOUS_PROVIDER_CONTROL_VERSION
        {
            return Err(ProtocolError::Malformed);
        }
        let mut account = [0u8; 32];
        account.copy_from_slice(&bytes[5..37]);
        let mut device = [0u8; 32];
        device.copy_from_slice(&bytes[37..69]);
        let authority_generation = read_u64(&bytes[69..77])?;
        let generation = read_u64(&bytes[77..85])?;
        let count = usize::from(bytes[85]);
        if count > MAX_RENDEZVOUS_CONTROL_PROVIDERS {
            return Err(ProtocolError::Malformed);
        }
        let mut providers = Vec::with_capacity(count);
        let mut cursor = PROVIDER_CONTROL_HEADER_LEN;
        for _ in 0..count {
            if cursor.checked_add(2).is_none_or(|end| end > bytes.len()) {
                return Err(ProtocolError::Malformed);
            }
            let length = usize::from(u16::from_be_bytes(
                bytes[cursor..cursor + 2]
                    .try_into()
                    .map_err(|_| ProtocolError::Malformed)?,
            ));
            cursor += 2;
            let end = cursor
                .checked_add(length)
                .and_then(|value| value.checked_add(32))
                .ok_or(ProtocolError::Malformed)?;
            if length == 0 || length > MAX_RENDEZVOUS_CONTROL_ORIGIN_BYTES || end > bytes.len() {
                return Err(ProtocolError::Malformed);
            }
            let origin_raw = &bytes[cursor..cursor + length];
            if origin_raw.contains(&0) {
                return Err(ProtocolError::Malformed);
            }
            let origin = core::str::from_utf8(origin_raw)
                .map_err(|_| ProtocolError::Malformed)?
                .into();
            cursor += length;
            let mut static_key = [0u8; 32];
            static_key.copy_from_slice(&bytes[cursor..cursor + 32]);
            cursor += 32;
            providers.push(RendezvousProviderDescriptor { origin, static_key });
        }
        if cursor != bytes.len() {
            return Err(ProtocolError::Malformed);
        }
        let control = Self {
            account,
            device,
            authority_generation,
            generation,
            providers,
        };
        control.validate()?;
        if control.encode()?.as_slice() != bytes {
            return Err(ProtocolError::Malformed);
        }
        Ok(control)
    }

    fn validate(&self) -> Result<()> {
        if self.authority_generation == 0
            || self.generation == 0
            || self.providers.len() > MAX_RENDEZVOUS_CONTROL_PROVIDERS
        {
            return Err(ProtocolError::Malformed);
        }
        for (index, provider) in self.providers.iter().enumerate() {
            let origin = provider.origin.as_bytes();
            if origin.is_empty()
                || origin.len() > MAX_RENDEZVOUS_CONTROL_ORIGIN_BYTES
                || origin.contains(&0)
                || provider.static_key == [0u8; 32]
                || self.providers[..index]
                    .last()
                    .is_some_and(|prior| prior >= provider)
            {
                return Err(ProtocolError::Malformed);
            }
        }
        Ok(())
    }
}

/// Whether bytes claim the rendezvous provider-control namespace.
pub fn is_rendezvous_provider_control(bytes: &[u8]) -> bool {
    bytes.starts_with(RENDEZVOUS_PROVIDER_CONTROL_MAGIC)
}

/// One route kind in an authenticated rendezvous record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum RendezvousRouteKind {
    /// Canonical libp2p multiaddress.
    Multiaddr = 1,
    /// Canonical mailbox-relay multiaddress.
    MailboxRelay = 2,
}

impl RendezvousRouteKind {
    fn parse(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Multiaddr),
            2 => Ok(Self::MailboxRelay),
            _ => Err(ProtocolError::Malformed),
        }
    }
}

/// One canonical authenticated route.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RendezvousRoute {
    /// Route interpretation.
    pub kind: RendezvousRouteKind,
    /// Canonical UTF-8 route value.
    pub value: String,
}

/// Fixed 4,096-byte plaintext opened only by a paired endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RendezvousRouteRecord {
    /// Hourly slot epoch.
    pub epoch: u64,
    /// Strictly increasing per-contact/direction/provider generation.
    pub generation: u64,
    /// Endpoint issuance time.
    pub issued_at: u64,
    /// Endpoint-selected route expiry.
    pub expires_at: u64,
    /// Complete route set for this source.
    pub routes: Vec<RendezvousRoute>,
}

impl RendezvousRouteRecord {
    /// Encode the canonical fixed-width plaintext.
    pub fn encode(&self) -> Result<[u8; RENDEZVOUS_RECORD_PLAINTEXT_LEN]> {
        self.validate_structure()?;
        let mut out = [0u8; RENDEZVOUS_RECORD_PLAINTEXT_LEN];
        out[0] = RENDEZVOUS_ROUTE_RECORD_VERSION;
        out[1] = 0;
        out[2..10].copy_from_slice(&self.epoch.to_be_bytes());
        out[10..18].copy_from_slice(&self.generation.to_be_bytes());
        out[18..26].copy_from_slice(&self.issued_at.to_be_bytes());
        out[26..34].copy_from_slice(&self.expires_at.to_be_bytes());
        out[34] = u8::try_from(self.routes.len()).map_err(|_| ProtocolError::Malformed)?;
        let mut cursor = ROUTE_RECORD_HEADER_LEN;
        for route in &self.routes {
            let value = route.value.as_bytes();
            let end = cursor
                .checked_add(3)
                .and_then(|value_start| value_start.checked_add(value.len()))
                .ok_or(ProtocolError::TooLarge)?;
            if end > out.len() {
                return Err(ProtocolError::TooLarge);
            }
            out[cursor] = route.kind as u8;
            out[cursor + 1..cursor + 3].copy_from_slice(
                &u16::try_from(value.len())
                    .map_err(|_| ProtocolError::TooLarge)?
                    .to_be_bytes(),
            );
            out[cursor + 3..end].copy_from_slice(value);
            cursor = end;
        }
        Ok(out)
    }

    /// Decode and enforce canonical shape, zero padding, route uniqueness and
    /// timestamp bounds. Contextual epoch/generation/clock checks are
    /// performed by [`Self::validate_acceptance`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != RENDEZVOUS_RECORD_PLAINTEXT_LEN
            || bytes[0] != RENDEZVOUS_ROUTE_RECORD_VERSION
            || bytes[1] != 0
        {
            return Err(ProtocolError::Malformed);
        }
        let epoch = read_u64(&bytes[2..10])?;
        let generation = read_u64(&bytes[10..18])?;
        let issued_at = read_u64(&bytes[18..26])?;
        let expires_at = read_u64(&bytes[26..34])?;
        let route_count = usize::from(bytes[34]);
        if route_count > MAX_RENDEZVOUS_ROUTES {
            return Err(ProtocolError::Malformed);
        }
        let mut routes = Vec::with_capacity(route_count);
        let mut cursor = ROUTE_RECORD_HEADER_LEN;
        for _ in 0..route_count {
            if cursor.checked_add(3).is_none_or(|end| end > bytes.len()) {
                return Err(ProtocolError::Malformed);
            }
            let kind = RendezvousRouteKind::parse(bytes[cursor])?;
            let value_len = usize::from(u16::from_be_bytes(
                bytes[cursor + 1..cursor + 3]
                    .try_into()
                    .map_err(|_| ProtocolError::Malformed)?,
            ));
            cursor += 3;
            if value_len == 0
                || value_len > MAX_RENDEZVOUS_ROUTE_BYTES
                || cursor
                    .checked_add(value_len)
                    .is_none_or(|end| end > bytes.len())
            {
                return Err(ProtocolError::Malformed);
            }
            let end = cursor + value_len;
            let raw = &bytes[cursor..end];
            if raw.contains(&0) {
                return Err(ProtocolError::Malformed);
            }
            let value = core::str::from_utf8(raw)
                .map_err(|_| ProtocolError::Malformed)?
                .into();
            let route = RendezvousRoute { kind, value };
            if routes.contains(&route) {
                return Err(ProtocolError::Malformed);
            }
            routes.push(route);
            cursor = end;
        }
        if bytes[cursor..].iter().any(|byte| *byte != 0) {
            return Err(ProtocolError::Malformed);
        }
        let record = Self {
            epoch,
            generation,
            issued_at,
            expires_at,
            routes,
        };
        record.validate_structure()?;
        // Enforce one canonical byte representation.
        if record.encode()?.as_slice() != bytes {
            return Err(ProtocolError::Malformed);
        }
        Ok(record)
    }

    /// Enforce contextual replay, rollback, queried-epoch and clock rules.
    ///
    /// `clock_floor` is the greatest effective wall-clock value retained for
    /// this relationship. Taking its maximum with `now` prevents a local
    /// rollback from reviving an already expired authenticated record.
    pub fn validate_acceptance(
        &self,
        expected_epoch: u64,
        now: u64,
        clock_floor: u64,
        greatest_generation: u64,
    ) -> Result<()> {
        let effective_now = now.max(clock_floor);
        if self.epoch != expected_epoch
            || self.generation < greatest_generation
            || self.expires_at <= effective_now
            || self.issued_at > effective_now.saturating_add(RENDEZVOUS_CLOCK_SKEW_SECS)
        {
            return Err(ProtocolError::Malformed);
        }
        Ok(())
    }

    fn validate_structure(&self) -> Result<()> {
        if self.generation == 0
            || self.routes.len() > MAX_RENDEZVOUS_ROUTES
            || self.issued_at > self.expires_at
            || self.expires_at.saturating_sub(self.issued_at) > u64::from(RENDEZVOUS_MAX_TTL_SECS)
        {
            return Err(ProtocolError::Malformed);
        }
        let mut encoded_len = ROUTE_RECORD_HEADER_LEN;
        for (index, route) in self.routes.iter().enumerate() {
            let value = route.value.as_bytes();
            if value.is_empty()
                || value.len() > MAX_RENDEZVOUS_ROUTE_BYTES
                || value.contains(&0)
                || core::str::from_utf8(value).is_err()
                || self.routes[..index]
                    .last()
                    .is_some_and(|prior| prior >= route)
            {
                return Err(ProtocolError::Malformed);
            }
            encoded_len = encoded_len
                .checked_add(3 + value.len())
                .ok_or(ProtocolError::TooLarge)?;
        }
        if encoded_len > RENDEZVOUS_RECORD_PLAINTEXT_LEN {
            return Err(ProtocolError::TooLarge);
        }
        Ok(())
    }
}

/// Exact fixed-width registration request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RendezvousRegisterRequest {
    /// Hourly opaque slot.
    pub slot: [u8; 32],
    /// Hourly epoch.
    pub epoch: u64,
    /// Requested receipt-relative retention.
    pub ttl_seconds: u32,
    /// Opaque endpoint-authenticated route record.
    pub sealed_record: [u8; RENDEZVOUS_SEALED_RECORD_LEN],
}

impl RendezvousRegisterRequest {
    /// Encode the exact binary HTTP body.
    pub fn encode(&self) -> Result<[u8; RENDEZVOUS_REGISTER_REQUEST_LEN]> {
        if self.ttl_seconds == 0 || self.ttl_seconds > RENDEZVOUS_MAX_TTL_SECS {
            return Err(ProtocolError::Malformed);
        }
        let mut out = [0u8; RENDEZVOUS_REGISTER_REQUEST_LEN];
        out[..32].copy_from_slice(&self.slot);
        out[32..40].copy_from_slice(&self.epoch.to_be_bytes());
        out[40..44].copy_from_slice(&self.ttl_seconds.to_be_bytes());
        out[44..].copy_from_slice(&self.sealed_record);
        Ok(out)
    }

    /// Parse an exact binary register body before any variable allocation.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != RENDEZVOUS_REGISTER_REQUEST_LEN {
            return Err(ProtocolError::Malformed);
        }
        let mut slot = [0u8; 32];
        slot.copy_from_slice(&bytes[..32]);
        let epoch = read_u64(&bytes[32..40])?;
        let ttl_seconds = u32::from_be_bytes(
            bytes[40..44]
                .try_into()
                .map_err(|_| ProtocolError::Malformed)?,
        );
        if ttl_seconds == 0 || ttl_seconds > RENDEZVOUS_MAX_TTL_SECS {
            return Err(ProtocolError::Malformed);
        }
        let mut sealed_record = [0u8; RENDEZVOUS_SEALED_RECORD_LEN];
        sealed_record.copy_from_slice(&bytes[44..]);
        Ok(Self {
            slot,
            epoch,
            ttl_seconds,
            sealed_record,
        })
    }
}

/// Exact fixed-width lookup request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RendezvousLookupRequest {
    /// Hourly opaque slot.
    pub slot: [u8; 32],
    /// Hourly epoch.
    pub epoch: u64,
}

impl RendezvousLookupRequest {
    /// Encode `slot || epoch || 24 zero bytes`.
    pub fn encode(&self) -> [u8; RENDEZVOUS_LOOKUP_REQUEST_LEN] {
        let mut out = [0u8; RENDEZVOUS_LOOKUP_REQUEST_LEN];
        out[..32].copy_from_slice(&self.slot);
        out[32..40].copy_from_slice(&self.epoch.to_be_bytes());
        out
    }

    /// Parse exact length and require canonical zero padding.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != RENDEZVOUS_LOOKUP_REQUEST_LEN || bytes[40..].iter().any(|byte| *byte != 0)
        {
            return Err(ProtocolError::Malformed);
        }
        let mut slot = [0u8; 32];
        slot.copy_from_slice(&bytes[..32]);
        Ok(Self {
            slot,
            epoch: read_u64(&bytes[32..40])?,
        })
    }
}

fn read_u64(bytes: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(
        bytes.try_into().map_err(|_| ProtocolError::Malformed)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> RendezvousRouteRecord {
        RendezvousRouteRecord {
            epoch: 12,
            generation: 7,
            issued_at: 43_200,
            expires_at: 46_800,
            routes: vec![
                RendezvousRoute {
                    kind: RendezvousRouteKind::Multiaddr,
                    value: "/ip4/192.0.2.1/udp/443/quic-v1/p2p/12D3KooWTest".into(),
                },
                RendezvousRoute {
                    kind: RendezvousRouteKind::MailboxRelay,
                    value: "/dns4/mail.example/tcp/443/p2p/12D3KooWRelay".into(),
                },
            ],
        }
    }

    #[test]
    fn route_record_is_fixed_canonical_and_bounded() {
        let encoded = record().encode().unwrap();
        assert_eq!(encoded.len(), RENDEZVOUS_RECORD_PLAINTEXT_LEN);
        assert_eq!(RendezvousRouteRecord::decode(&encoded).unwrap(), record());
        record().validate_acceptance(12, 43_201, 43_200, 6).unwrap();

        let mut nonzero_padding = encoded;
        *nonzero_padding.last_mut().unwrap() = 1;
        assert!(RendezvousRouteRecord::decode(&nonzero_padding).is_err());

        let mut duplicate = record();
        duplicate.routes.push(duplicate.routes[0].clone());
        assert!(duplicate.encode().is_err());

        let mut reordered = record();
        reordered.routes.reverse();
        assert!(reordered.encode().is_err());
    }

    #[test]
    fn replay_expiry_future_and_rollback_fail_closed() {
        let value = record();
        assert!(value.validate_acceptance(13, 43_201, 0, 0).is_err());
        assert!(value.validate_acceptance(12, 43_201, 0, 8).is_err());
        assert!(value.validate_acceptance(12, 47_000, 0, 7).is_err());
        assert!(value.validate_acceptance(12, 42_000, 47_000, 7).is_err());
        let mut future = value;
        future.issued_at = 44_000;
        future.expires_at = 45_000;
        assert!(future.validate_acceptance(12, 43_000, 0, 0).is_err());
    }

    #[test]
    fn fixed_http_bodies_roundtrip_and_reject_wrong_shape() {
        let register = RendezvousRegisterRequest {
            slot: [3u8; 32],
            epoch: 9,
            ttl_seconds: 7_200,
            sealed_record: [4u8; RENDEZVOUS_SEALED_RECORD_LEN],
        };
        let encoded = register.encode().unwrap();
        assert_eq!(encoded.len(), RENDEZVOUS_REGISTER_REQUEST_LEN);
        assert_eq!(
            RendezvousRegisterRequest::decode(&encoded).unwrap(),
            register
        );
        assert!(RendezvousRegisterRequest::decode(&encoded[..encoded.len() - 1]).is_err());

        let lookup = RendezvousLookupRequest {
            slot: [5u8; 32],
            epoch: 10,
        };
        let encoded = lookup.encode();
        assert_eq!(RendezvousLookupRequest::decode(&encoded).unwrap(), lookup);
        let mut malformed = encoded;
        malformed[63] = 1;
        assert!(RendezvousLookupRequest::decode(&malformed).is_err());
    }

    #[test]
    fn provider_control_is_device_bound_sorted_and_canonical() {
        let control = RendezvousProviderControl {
            account: [1u8; 32],
            device: [2u8; 32],
            authority_generation: 3,
            generation: 4,
            providers: vec![
                RendezvousProviderDescriptor {
                    origin: "https://a.example".into(),
                    static_key: [5u8; 32],
                },
                RendezvousProviderDescriptor {
                    origin: "https://b.example".into(),
                    static_key: [6u8; 32],
                },
            ],
        };
        let encoded = control.encode().unwrap();
        assert!(is_rendezvous_provider_control(&encoded));
        assert_eq!(
            RendezvousProviderControl::decode(&encoded).unwrap(),
            control
        );

        let mut unsorted = control;
        unsorted.providers.swap(0, 1);
        assert!(unsorted.encode().is_err());
    }
}
