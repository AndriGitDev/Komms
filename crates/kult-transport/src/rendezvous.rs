//! Provider descriptors and a fixed-shape ADR-0018 client boundary.

use async_trait::async_trait;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use kult_crypto::{
    rendezvous_provider_id, MAX_RENDEZVOUS_PROVIDER_ORIGIN_BYTES, RENDEZVOUS_SEALED_RECORD_LEN,
};
use kult_protocol::{
    RendezvousLookupRequest, RendezvousRegisterRequest, RendezvousRoute, RendezvousRouteKind,
    RENDEZVOUS_REGISTER_ACK_LEN,
};

use crate::{internet::parse_addr, DeliveryHint, Result, TransportError};

/// Maximum configured rendezvous providers consumed by one client.
pub const MAX_RENDEZVOUS_PROVIDERS: usize = 8;

/// Canonical, authenticated provider descriptor.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RendezvousProvider {
    origin: String,
    static_key: [u8; 32],
    provider_id: [u8; 32],
}

impl RendezvousProvider {
    /// Validate one canonical HTTPS origin and bind its service static key.
    ///
    /// The origin is lower-case `https://authority` with no path, trailing
    /// slash, query, fragment, user information or whitespace. Bracketed IPv6
    /// and an explicit decimal port are permitted.
    pub fn new(origin: String, static_key: [u8; 32]) -> Result<Self> {
        if !canonical_https_origin(&origin) || static_key == [0u8; 32] {
            return Err(TransportError::UnsupportedHint);
        }
        let provider_id = rendezvous_provider_id(origin.as_bytes(), &static_key)
            .map_err(|_| TransportError::UnsupportedHint)?;
        Ok(Self {
            origin,
            static_key,
            provider_id,
        })
    }

    /// Canonical HTTPS origin.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Service static key bound into the provider id.
    pub fn static_key(&self) -> [u8; 32] {
        self.static_key
    }

    /// Provider-separation id.
    pub fn provider_id(&self) -> [u8; 32] {
        self.provider_id
    }
}

/// Fixed binary register/lookup transport.
///
/// Implementations terminate TLS in the dedicated rendezvous component and
/// must not place a slot in a URL, redirect, compress, attach cookies, reflect
/// request ids or expose hit/miss through response shape.
#[async_trait]
pub trait RendezvousClient: Send + Sync {
    /// Submit one fixed register body. The opaque acknowledgement confirms
    /// only service processing; callers must self-lookup before recording a
    /// successful registration.
    async fn register(
        &self,
        provider: &RendezvousProvider,
        request: &RendezvousRegisterRequest,
    ) -> Result<[u8; RENDEZVOUS_REGISTER_ACK_LEN]>;

    /// Submit one fixed lookup body and return exactly 4,136 bytes for both
    /// hits and misses.
    async fn lookup(
        &self,
        provider: &RendezvousProvider,
        request: &RendezvousLookupRequest,
    ) -> Result<[u8; RENDEZVOUS_SEALED_RECORD_LEN]>;
}

/// Convert an authenticated record route into the existing transport hint,
/// rejecting non-canonical or non-addressable multiaddresses.
pub fn rendezvous_route_hint(route: &RendezvousRoute) -> Result<DeliveryHint> {
    if parse_addr(&route.value).is_none() {
        return Err(TransportError::UnsupportedHint);
    }
    Ok(match route.kind {
        RendezvousRouteKind::Multiaddr => DeliveryHint::Multiaddr(route.value.clone()),
        RendezvousRouteKind::MailboxRelay => DeliveryHint::Relay(route.value.clone()),
    })
}

/// Convert a local transport hint into a canonical rendezvous route.
pub fn rendezvous_record_route(hint: &DeliveryHint) -> Result<RendezvousRoute> {
    let (kind, value) = match hint {
        DeliveryHint::Multiaddr(value) => (RendezvousRouteKind::Multiaddr, value),
        DeliveryHint::Relay(value) => (RendezvousRouteKind::MailboxRelay, value),
        DeliveryHint::Spool(_) | DeliveryHint::MeshNode(_) => {
            return Err(TransportError::UnsupportedHint);
        }
    };
    if parse_addr(value).is_none() {
        return Err(TransportError::UnsupportedHint);
    }
    Ok(RendezvousRoute {
        kind,
        value: value.clone(),
    })
}

fn canonical_https_origin(origin: &str) -> bool {
    const PREFIX: &str = "https://";
    if origin.len() <= PREFIX.len()
        || origin.len() > MAX_RENDEZVOUS_PROVIDER_ORIGIN_BYTES
        || !origin.starts_with(PREFIX)
        || origin.ends_with('/')
    {
        return false;
    }
    let authority = &origin[PREFIX.len()..];
    if authority.is_empty()
        || authority.bytes().any(|byte| {
            byte.is_ascii_whitespace()
                || byte.is_ascii_uppercase()
                || matches!(byte, b'/' | b'?' | b'#' | b'@' | 0)
        })
    {
        return false;
    }
    let port = if let Some(bracketed) = authority.strip_prefix('[') {
        let Some(close) = bracketed.find(']') else {
            return false;
        };
        let host = &bracketed[..close];
        let suffix = &bracketed[close + 1..];
        if host.is_empty()
            || !Ipv6Addr::from_str(host).is_ok_and(|address| address.to_string() == host)
        {
            return false;
        }
        if suffix.is_empty() {
            None
        } else {
            let Some(port) = suffix.strip_prefix(':') else {
                return false;
            };
            Some(port)
        }
    } else {
        if authority.matches(':').count() > 1 {
            return false;
        }
        let (host, port) = authority
            .rsplit_once(':')
            .map_or((authority, None), |(host, port)| (host, Some(port)));
        if !canonical_host(host) {
            return false;
        }
        port
    };
    port.is_none_or(canonical_nondefault_port)
}

fn canonical_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 || host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    if let Ok(address) = Ipv4Addr::from_str(host) {
        return address.to_string() == host;
    }
    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    })
}

fn canonical_nondefault_port(port: &str) -> bool {
    port.parse::<u16>()
        .is_ok_and(|value| value != 0 && value != 443 && value.to_string() == port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_origins_are_canonical_and_key_bound() {
        let provider =
            RendezvousProvider::new("https://rv.example:8443".into(), [1u8; 32]).unwrap();
        assert_eq!(provider.origin(), "https://rv.example:8443");
        assert_ne!(provider.provider_id(), [0u8; 32]);
        assert_ne!(
            provider.provider_id(),
            RendezvousProvider::new("https://rv.example:8443".into(), [2u8; 32])
                .unwrap()
                .provider_id()
        );
        for invalid in [
            "http://rv.example",
            "https://RV.example",
            "https://rv.example/",
            "https://user@rv.example",
            "https://rv.example/path",
            "https://rv.example?q",
            "https://rv example",
            "https://rv.example:443",
            "https://rv.example:0443",
            "https://rv.example:0",
            "https://-rv.example",
            "https://rv-.example",
            "https://rv..example",
            "https://:",
            "https://2001:db8::1",
            "https://[2001:0db8::1]",
        ] {
            assert!(RendezvousProvider::new(invalid.into(), [1u8; 32]).is_err());
        }
        assert!(RendezvousProvider::new("https://[2001:db8::1]:8443".into(), [1u8; 32]).is_ok());
    }
}
