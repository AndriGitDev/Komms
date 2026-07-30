//! Capability-scoped first-contact discovery (ADR-0031).
//!
//! Connect codes separate the stable account fingerprint from a random,
//! rotatable reachability capability. DHT values are exact-size encrypted
//! records: a storage peer learns neither the account nor the contained
//! routes, while a code holder can verify the complete device-authority and
//! prekey chain before using any route.

use alloc::{string::String, vec, vec::Vec};

use hmac::{Hmac, Mac};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};

use crate::{
    util, CryptoError, DeviceAuthorityCertificate, DeviceAuthorityManifest, Identity,
    IdentityPublic, PrekeyBundle, Result, MAX_DEVICE_AUTHORITY_BYTES, MAX_PREKEY_BUNDLE_BYTES,
};

/// Text prefix for a version-two Connect code.
pub const CONNECT_CODE_PREFIX: &str = "kc2";
/// Bytes carried before base32 encoding: identity digest, capability, checksum.
pub const CONNECT_CODE_PAYLOAD_BYTES: usize = 68;
/// Seconds in one discovery epoch (seven days).
pub const DISCOVERY_EPOCH_SECS: u64 = 7 * 24 * 60 * 60;
/// Clock grace before and after an encoded discovery epoch.
pub const DISCOVERY_CLOCK_GRACE_SECS: u64 = 24 * 60 * 60;
/// Earliest relative epoch published during maintenance.
pub const DISCOVERY_PUBLISH_EPOCH_BEHIND: u64 = 1;
/// Latest relative epoch published during maintenance.
pub const DISCOVERY_PUBLISH_EPOCH_AHEAD: u64 = 4;
/// Adjacent epochs queried on either side of the local epoch.
pub const DISCOVERY_LOOKUP_EPOCH_ADJACENCY: u64 = 1;
/// Exact encrypted outer DHT value size (1.125 MiB).
///
/// This accommodates the complete one-MiB bounded ADR-0026 proof, two
/// maximal prekey bundles, bounded route metadata, and fixed codec overhead.
pub const DISCOVERY_RECORD_SIZE: usize = 1_179_648;
/// Maximum distinct candidate values retained for one locator.
pub const MAX_DISCOVERY_CANDIDATES: usize = 8;
/// Maximum ingress devices in one public record.
pub const MAX_DISCOVERY_INGRESS_DEVICES: usize = 2;
/// Maximum introduction routes in one public record.
pub const MAX_DISCOVERY_ROUTES: usize = 3;
/// Maximum bytes in one encoded introduction route.
pub const MAX_DISCOVERY_ROUTE_BYTES: usize = 1024;
/// Discovery record format version.
pub const DISCOVERY_RECORD_VERSION: u16 = 2;

const CONNECT_CHECKSUM_DOMAIN: &[u8] = b"Komms-Connect-Code-v2";
const LOCATOR_DOMAIN: &[u8] = b"Komms-DHT-Locator-v2";
const RECORD_KEY_DOMAIN: &[u8] = b"Komms-DHT-Record-Key-v2";
const RECORD_AAD_DOMAIN: &[u8] = b"Komms-DHT-Record-v2";
const RECORD_SIGNATURE_DOMAIN: &[u8] = b"Komms-DHT-Record-Signature-v2";
const INTRODUCTION_KEY_DOMAIN: &[u8] = b"Komms-Introduction-Mailbox-Key-v2";
const INTRODUCTION_TOKEN_DOMAIN: &[u8] = b"Komms-Introduction-Mailbox-Token-v2";
const RECORD_MAGIC: &[u8; 4] = b"KDR2";
const NONCE_AND_TAG_BYTES: usize = util::NONCE_LEN + util::TAG_LEN;
const RECORD_PLAINTEXT_SIZE: usize = DISCOVERY_RECORD_SIZE - NONCE_AND_TAG_BYTES;
const RECORD_SIGNATURE_BYTES: usize = 64;
const RECORD_SIGNATURE_OFFSET: usize = RECORD_PLAINTEXT_SIZE - RECORD_SIGNATURE_BYTES;
const MAX_DISCOVERY_CERTIFICATE_BYTES: usize = 4096;

/// A versioned human-shareable discovery capability bound to one stable
/// account fingerprint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectCode {
    identity_digest: [u8; 32],
    capability: [u8; 32],
}

impl ConnectCode {
    /// Bind an existing non-zero random capability to `account`.
    pub fn new(account: &IdentityPublic, capability: [u8; 32]) -> Result<Self> {
        account.verify()?;
        if capability == [0u8; 32] {
            return Err(CryptoError::InvalidKey);
        }
        Ok(Self {
            identity_digest: account.address_digest(),
            capability,
        })
    }

    /// Generate a fresh random capability for `account`.
    pub fn generate(account: &IdentityPublic, rng: &mut impl CryptoRngCore) -> Result<Self> {
        let mut capability = [0u8; 32];
        while capability == [0u8; 32] {
            rng.fill_bytes(&mut capability);
        }
        Self::new(account, capability)
    }

    /// Stable account-address digest carried by the code.
    pub fn identity_digest(&self) -> [u8; 32] {
        self.identity_digest
    }

    /// Bearer discovery capability.
    pub fn capability(&self) -> [u8; 32] {
        self.capability
    }

    /// Canonical lowercase base32 text.
    pub fn encode(&self) -> String {
        let mut payload = [0u8; CONNECT_CODE_PAYLOAD_BYTES];
        payload[..32].copy_from_slice(&self.identity_digest);
        payload[32..64].copy_from_slice(&self.capability);
        let checksum = connect_checksum(&payload[..64]);
        payload[64..].copy_from_slice(&checksum);
        let mut out = String::from(CONNECT_CODE_PREFIX);
        out.push_str(&util::base32_lower_nopad(&payload));
        out
    }

    /// Strictly parse canonical Connect-code text and verify its checksum.
    pub fn parse(text: &str) -> Result<Self> {
        let encoded = text
            .strip_prefix(CONNECT_CODE_PREFIX)
            .ok_or(CryptoError::InvalidMessage)?;
        let decoded =
            util::base32_lower_nopad_decode(encoded).ok_or(CryptoError::InvalidMessage)?;
        let payload: [u8; CONNECT_CODE_PAYLOAD_BYTES] = decoded
            .try_into()
            .map_err(|_| CryptoError::InvalidMessage)?;
        if text != {
            let mut canonical = String::from(CONNECT_CODE_PREFIX);
            canonical.push_str(&util::base32_lower_nopad(&payload));
            canonical
        } || payload[64..] != connect_checksum(&payload[..64])
        {
            return Err(CryptoError::InvalidMessage);
        }
        let identity_digest = payload[..32]
            .try_into()
            .map_err(|_| CryptoError::InvalidMessage)?;
        let capability = payload[32..64]
            .try_into()
            .map_err(|_| CryptoError::InvalidMessage)?;
        if identity_digest == [0u8; 32] || capability == [0u8; 32] {
            return Err(CryptoError::InvalidMessage);
        }
        Ok(Self {
            identity_digest,
            capability,
        })
    }
}

/// Route class carried inside an encrypted discovery record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DiscoveryRouteKind {
    /// Recipient-selected durable introduction mailbox.
    IntroductionMailbox = 1,
    /// Explicitly warned direct route in Sovereign mode only.
    SovereignDirect = 2,
}

impl TryFrom<u8> for DiscoveryRouteKind {
    type Error = CryptoError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::IntroductionMailbox),
            2 => Ok(Self::SovereignDirect),
            _ => Err(CryptoError::InvalidMessage),
        }
    }
}

/// One bounded opaque route in a discovery record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryRoute {
    /// Route policy class.
    pub kind: DiscoveryRouteKind,
    /// Higher-layer canonical route bytes.
    pub value: Vec<u8>,
}

/// One account-authorized ingress device and its device-signed prekeys.
#[derive(Clone)]
pub struct DiscoveryIngressBundle {
    /// Immutable device certificate introduced by the authority proof.
    pub certificate: DeviceAuthorityCertificate,
    /// Device-signed prekey and admission descriptor.
    pub prekey: PrekeyBundle,
}

/// Verified cleartext contents of one capability-scoped DHT record.
#[derive(Clone)]
pub struct DiscoveryRecord {
    /// Capability-derived locator bound inside the record.
    pub locator: [u8; 32],
    /// Weekly epoch for this exact locator.
    pub epoch: u64,
    /// Monotonic publisher generation.
    pub generation: u64,
    /// Coarse issue time.
    pub issued_at: u64,
    /// Exact end of the encoded epoch's validity grace.
    pub expires_at: u64,
    /// Stable public account.
    pub account: IdentityPublic,
    /// Complete bounded ADR-0026 proof.
    pub authority: DeviceAuthorityManifest,
    /// One or two independently addressable ingress devices.
    pub ingress: Vec<DiscoveryIngressBundle>,
    /// At most three bounded public introduction routes.
    pub routes: Vec<DiscoveryRoute>,
    /// Active physical device that signed the complete padded record.
    pub signer: [u8; 32],
    digest: [u8; 32],
}

impl DiscoveryRecord {
    /// Digest of the complete canonical plaintext, including zero padding and
    /// signature. Used only for deterministic valid-record selection.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Verify structural, authority, prekey, route, and time invariants.
    pub fn verify(&self, now: u64) -> Result<()> {
        if self.generation == 0
            || self.issued_at > self.expires_at
            || self.expires_at != discovery_epoch_valid_until(self.epoch)?
            || self.account.address_digest() == [0u8; 32]
            || self.authority.account() != &self.account
            || self.ingress.is_empty()
            || self.ingress.len() > MAX_DISCOVERY_INGRESS_DEVICES
            || self.routes.len() > MAX_DISCOVERY_ROUTES
            || self.routes.iter().any(|route| {
                route.value.is_empty() || route.value.len() > MAX_DISCOVERY_ROUTE_BYTES
            })
        {
            return Err(CryptoError::InvalidMessage);
        }
        self.account.verify()?;
        self.authority.verify()?;
        if self.authority.active_certificate(&self.signer).is_none() {
            return Err(CryptoError::InvalidMessage);
        }
        let mut prior_route: Option<(u8, &[u8])> = None;
        for route in &self.routes {
            let current = (route.kind as u8, route.value.as_slice());
            if prior_route.is_some_and(|prior| prior >= current) {
                return Err(CryptoError::InvalidMessage);
            }
            prior_route = Some(current);
        }
        let mut prior_device = None;
        for ingress in &self.ingress {
            ingress.certificate.verify()?;
            let device = ingress.certificate.device_id();
            if prior_device.is_some_and(|prior| prior >= device)
                || ingress.certificate.account != self.account
                || self
                    .authority
                    .active_certificate(&device)
                    .is_none_or(|certificate| certificate != &ingress.certificate)
                || ingress.prekey.identity != ingress.certificate.device
                || ingress.prekey.opk.is_some()
                || !ingress.prekey.transport_hints().is_empty()
            {
                return Err(CryptoError::InvalidMessage);
            }
            ingress.prekey.verify(now)?;
            ingress.prekey.verify_admission(now)?;
            prior_device = Some(device);
        }
        if now != 0 {
            let valid_from = discovery_epoch_valid_from(self.epoch);
            if now < valid_from || now > self.expires_at {
                return Err(CryptoError::InvalidMessage);
            }
        }
        Ok(())
    }
}

/// Current weekly discovery epoch.
pub fn discovery_epoch(now: u64) -> u64 {
    now / DISCOVERY_EPOCH_SECS
}

/// Capability-derived weekly locator.
pub fn discovery_locator(capability: &[u8; 32], epoch: u64) -> [u8; 32] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(capability).expect("HMAC accepts every key length");
    mac.update(LOCATOR_DOMAIN);
    mac.update(&epoch.to_be_bytes());
    mac.finalize().into_bytes().into()
}

/// Separate rotating device-scoped token for offline introductions.
pub fn discovery_introduction_token(
    capability: &[u8; 32],
    recipient_device: &[u8; 32],
    day_epoch: u64,
) -> [u8; 32] {
    let key = util::hkdf32(Some(recipient_device), capability, INTRODUCTION_KEY_DOMAIN);
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key.as_ref()).expect("HMAC accepts every key length");
    mac.update(INTRODUCTION_TOKEN_DOMAIN);
    mac.update(&day_epoch.to_be_bytes());
    mac.finalize().into_bytes().into()
}

/// First second at which a record for `epoch` is client-valid.
pub fn discovery_epoch_valid_from(epoch: u64) -> u64 {
    epoch
        .saturating_mul(DISCOVERY_EPOCH_SECS)
        .saturating_sub(DISCOVERY_CLOCK_GRACE_SECS)
}

/// Final second at which a record for `epoch` is client-valid.
pub fn discovery_epoch_valid_until(epoch: u64) -> Result<u64> {
    epoch
        .checked_add(1)
        .and_then(|next| next.checked_mul(DISCOVERY_EPOCH_SECS))
        .and_then(|end| end.checked_add(DISCOVERY_CLOCK_GRACE_SECS))
        .ok_or(CryptoError::InvalidMessage)
}

/// Build, sign, pad, and encrypt one exact-size DHT value.
#[allow(clippy::too_many_arguments)]
pub fn seal_discovery_record(
    code: &ConnectCode,
    epoch: u64,
    generation: u64,
    issued_at: u64,
    account: IdentityPublic,
    authority: DeviceAuthorityManifest,
    ingress: Vec<DiscoveryIngressBundle>,
    mut routes: Vec<DiscoveryRoute>,
    signer: &Identity,
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<u8>> {
    if code.identity_digest != account.address_digest() || generation == 0 {
        return Err(CryptoError::InvalidMessage);
    }
    routes.sort_by(|left, right| {
        (left.kind as u8, left.value.as_slice()).cmp(&(right.kind as u8, right.value.as_slice()))
    });
    let locator = discovery_locator(&code.capability, epoch);
    let expires_at = discovery_epoch_valid_until(epoch)?;
    let mut record = DiscoveryRecord {
        locator,
        epoch,
        generation,
        issued_at,
        expires_at,
        account,
        authority,
        ingress,
        routes,
        signer: signer.public().ed,
        digest: [0u8; 32],
    };
    record
        .ingress
        .sort_by_key(|entry| entry.certificate.device_id());
    record.verify(0)?;
    let mut plain = encode_unsigned_record(&record)?;
    let digest: [u8; 32] = Sha256::digest(&plain[..RECORD_SIGNATURE_OFFSET]).into();
    let signature = signer.sign_domain(RECORD_SIGNATURE_DOMAIN, &digest);
    plain[RECORD_SIGNATURE_OFFSET..].copy_from_slice(&signature);
    record.digest = Sha256::digest(&plain).into();
    let key = discovery_record_key(&code.capability, &locator);
    let aad = discovery_record_aad(&locator, epoch);
    let sealed = util::aead_seal(&key, &aad, &plain, rng);
    if sealed.len() != DISCOVERY_RECORD_SIZE {
        return Err(CryptoError::InvalidMessage);
    }
    Ok(sealed)
}

/// Open and fully verify one exact-size candidate for `code` and `epoch`.
pub fn open_discovery_record(
    code: &ConnectCode,
    epoch: u64,
    sealed: &[u8],
    now: u64,
) -> Result<DiscoveryRecord> {
    if sealed.len() != DISCOVERY_RECORD_SIZE {
        return Err(CryptoError::InvalidMessage);
    }
    let locator = discovery_locator(&code.capability, epoch);
    let key = discovery_record_key(&code.capability, &locator);
    let aad = discovery_record_aad(&locator, epoch);
    let plain = util::aead_open(&key, &aad, sealed)?;
    if plain.len() != RECORD_PLAINTEXT_SIZE {
        return Err(CryptoError::InvalidMessage);
    }
    let mut record = decode_record(&plain)?;
    if record.locator != locator
        || record.epoch != epoch
        || record.account.address_digest() != code.identity_digest
    {
        return Err(CryptoError::InvalidMessage);
    }
    let signature: [u8; 64] = plain[RECORD_SIGNATURE_OFFSET..]
        .try_into()
        .map_err(|_| CryptoError::InvalidMessage)?;
    let digest: [u8; 32] = Sha256::digest(&plain[..RECORD_SIGNATURE_OFFSET]).into();
    let certificate = record
        .authority
        .active_certificate(&record.signer)
        .ok_or(CryptoError::InvalidMessage)?;
    certificate
        .device
        .verify_domain(RECORD_SIGNATURE_DOMAIN, &digest, &signature)?;
    record.digest = Sha256::digest(&plain).into();
    record.verify(now)?;
    Ok(record)
}

fn encode_unsigned_record(record: &DiscoveryRecord) -> Result<Vec<u8>> {
    let authority = record.authority.encode()?;
    if authority.len() > MAX_DEVICE_AUTHORITY_BYTES + 4 {
        return Err(CryptoError::InvalidMessage);
    }
    let mut semantic = Vec::new();
    semantic.extend_from_slice(RECORD_MAGIC);
    semantic.extend_from_slice(&DISCOVERY_RECORD_VERSION.to_be_bytes());
    semantic.extend_from_slice(&record.locator);
    semantic.extend_from_slice(&record.epoch.to_be_bytes());
    semantic.extend_from_slice(&record.generation.to_be_bytes());
    semantic.extend_from_slice(&record.issued_at.to_be_bytes());
    semantic.extend_from_slice(&record.expires_at.to_be_bytes());
    append_identity(&mut semantic, &record.account);
    append_len_u32(&mut semantic, authority.len())?;
    semantic.extend_from_slice(&authority);
    semantic.push(u8::try_from(record.ingress.len()).map_err(|_| CryptoError::InvalidMessage)?);
    for ingress in &record.ingress {
        let certificate =
            postcard::to_allocvec(&ingress.certificate).map_err(|_| CryptoError::Serialization)?;
        let prekey = ingress.prekey.encode();
        if certificate.len() > MAX_DISCOVERY_CERTIFICATE_BYTES
            || prekey.len() > MAX_PREKEY_BUNDLE_BYTES
        {
            return Err(CryptoError::InvalidMessage);
        }
        append_len_u16(&mut semantic, certificate.len())?;
        semantic.extend_from_slice(&certificate);
        append_len_u32(&mut semantic, prekey.len())?;
        semantic.extend_from_slice(&prekey);
    }
    semantic.push(u8::try_from(record.routes.len()).map_err(|_| CryptoError::InvalidMessage)?);
    for route in &record.routes {
        semantic.push(route.kind as u8);
        append_len_u16(&mut semantic, route.value.len())?;
        semantic.extend_from_slice(&route.value);
    }
    semantic.extend_from_slice(&record.signer);
    if semantic.len() > RECORD_SIGNATURE_OFFSET {
        return Err(CryptoError::InvalidMessage);
    }
    let mut plain = vec![0u8; RECORD_PLAINTEXT_SIZE];
    plain[..semantic.len()].copy_from_slice(&semantic);
    Ok(plain)
}

fn decode_record(plain: &[u8]) -> Result<DiscoveryRecord> {
    let mut reader = Reader::new(&plain[..RECORD_SIGNATURE_OFFSET]);
    if reader.take(4)? != RECORD_MAGIC || reader.u16()? != DISCOVERY_RECORD_VERSION {
        return Err(CryptoError::InvalidMessage);
    }
    let locator = reader.array()?;
    let epoch = reader.u64()?;
    let generation = reader.u64()?;
    let issued_at = reader.u64()?;
    let expires_at = reader.u64()?;
    let account = read_identity(&mut reader)?;
    let authority_len = reader.u32_usize()?;
    if authority_len > MAX_DEVICE_AUTHORITY_BYTES + 4 {
        return Err(CryptoError::InvalidMessage);
    }
    let authority = DeviceAuthorityManifest::decode(reader.take(authority_len)?)?;
    let ingress_count = usize::from(reader.u8()?);
    if ingress_count == 0 || ingress_count > MAX_DISCOVERY_INGRESS_DEVICES {
        return Err(CryptoError::InvalidMessage);
    }
    let mut ingress = Vec::with_capacity(ingress_count);
    for _ in 0..ingress_count {
        let certificate_len = usize::from(reader.u16()?);
        if certificate_len == 0 || certificate_len > MAX_DISCOVERY_CERTIFICATE_BYTES {
            return Err(CryptoError::InvalidMessage);
        }
        let certificate_bytes = reader.take(certificate_len)?;
        let (certificate, remainder): (DeviceAuthorityCertificate, &[u8]) =
            postcard::take_from_bytes(certificate_bytes).map_err(|_| CryptoError::Serialization)?;
        if !remainder.is_empty() {
            return Err(CryptoError::Serialization);
        }
        let prekey_len = reader.u32_usize()?;
        if prekey_len == 0 || prekey_len > MAX_PREKEY_BUNDLE_BYTES {
            return Err(CryptoError::InvalidMessage);
        }
        let prekey = PrekeyBundle::decode(reader.take(prekey_len)?)?;
        ingress.push(DiscoveryIngressBundle {
            certificate,
            prekey,
        });
    }
    let route_count = usize::from(reader.u8()?);
    if route_count > MAX_DISCOVERY_ROUTES {
        return Err(CryptoError::InvalidMessage);
    }
    let mut routes = Vec::with_capacity(route_count);
    for _ in 0..route_count {
        let kind = DiscoveryRouteKind::try_from(reader.u8()?)?;
        let length = usize::from(reader.u16()?);
        if length == 0 || length > MAX_DISCOVERY_ROUTE_BYTES {
            return Err(CryptoError::InvalidMessage);
        }
        routes.push(DiscoveryRoute {
            kind,
            value: reader.take(length)?.to_vec(),
        });
    }
    let signer = reader.array()?;
    if reader.remaining().iter().any(|byte| *byte != 0) {
        return Err(CryptoError::InvalidMessage);
    }
    Ok(DiscoveryRecord {
        locator,
        epoch,
        generation,
        issued_at,
        expires_at,
        account,
        authority,
        ingress,
        routes,
        signer,
        digest: [0u8; 32],
    })
}

fn connect_checksum(payload: &[u8]) -> [u8; 4] {
    let mut hash = Sha256::new();
    hash.update(CONNECT_CHECKSUM_DOMAIN);
    hash.update(payload);
    let digest = hash.finalize();
    digest[..4].try_into().expect("slice has exact length")
}

fn discovery_record_key(capability: &[u8; 32], locator: &[u8; 32]) -> [u8; 32] {
    *util::hkdf32(Some(locator), capability, RECORD_KEY_DOMAIN)
}

fn discovery_record_aad(locator: &[u8; 32], epoch: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(RECORD_AAD_DOMAIN.len() + 32 + 8);
    aad.extend_from_slice(RECORD_AAD_DOMAIN);
    aad.extend_from_slice(locator);
    aad.extend_from_slice(&epoch.to_be_bytes());
    aad
}

fn append_identity(out: &mut Vec<u8>, identity: &IdentityPublic) {
    out.extend_from_slice(&identity.ed);
    out.extend_from_slice(&identity.x);
    out.extend_from_slice(&identity.cross_sig);
}

fn read_identity(reader: &mut Reader<'_>) -> Result<IdentityPublic> {
    Ok(IdentityPublic {
        ed: reader.array()?,
        x: reader.array()?,
        cross_sig: reader.array()?,
    })
}

fn append_len_u16(out: &mut Vec<u8>, length: usize) -> Result<()> {
    out.extend_from_slice(
        &u16::try_from(length)
            .map_err(|_| CryptoError::InvalidMessage)?
            .to_be_bytes(),
    );
    Ok(())
}

fn append_len_u32(out: &mut Vec<u8>, length: usize) -> Result<()> {
    out.extend_from_slice(
        &u32::try_from(length)
            .map_err(|_| CryptoError::InvalidMessage)?
            .to_be_bytes(),
    );
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CryptoError::InvalidMessage)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CryptoError::InvalidMessage)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| CryptoError::InvalidMessage)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32_usize(&mut self) -> Result<usize> {
        usize::try_from(u32::from_be_bytes(self.array()?)).map_err(|_| CryptoError::InvalidMessage)
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.offset..]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AdmissionPolicy, DeviceAuthorityManifest, PqPrekeySecret, SignedPrekeySecret};
    use rand::{rngs::StdRng, SeedableRng};

    const NOW: u64 = 1_900_000_000;

    fn fixture(
        rng: &mut StdRng,
    ) -> (
        ConnectCode,
        IdentityPublic,
        Identity,
        DeviceAuthorityManifest,
        DiscoveryIngressBundle,
    ) {
        let root = Identity::generate(rng);
        let device = Identity::generate(rng);
        let manifest =
            DeviceAuthorityManifest::initial(&root, &device, "Phone".into(), NOW, rng).unwrap();
        let spk = SignedPrekeySecret::generate(rng, 1);
        let pqspk = PqPrekeySecret::generate(rng, 2);
        let epoch = discovery_epoch(NOW);
        let valid_from = discovery_epoch_valid_from(epoch);
        let mut prekey = PrekeyBundle::build(
            &device,
            &spk,
            &pqspk,
            None,
            discovery_epoch_valid_until(epoch).unwrap(),
            Vec::new(),
        );
        prekey
            .attach_admission(&device, valid_from, AdmissionPolicy::default(), None)
            .unwrap();
        let code = ConnectCode::generate(&root.public(), rng).unwrap();
        (
            code,
            root.public(),
            device,
            manifest.clone(),
            DiscoveryIngressBundle {
                certificate: manifest.devices()[0].certificate.clone(),
                prekey,
            },
        )
    }

    #[test]
    fn connect_code_known_shape_checksum_and_canonical_text() {
        let fixed = ConnectCode {
            identity_digest: [1; 32],
            capability: [2; 32],
        };
        assert_eq!(
            fixed.encode(),
            "kc2aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeavbh5ipi"
        );
        assert_eq!(ConnectCode::parse(&fixed.encode()).unwrap(), fixed);

        let mut rng = StdRng::seed_from_u64(0x3100);
        let root = Identity::generate(&mut rng);
        let code = ConnectCode::new(&root.public(), [0x42; 32]).unwrap();
        let text = code.encode();
        assert!(text.starts_with(CONNECT_CODE_PREFIX));
        assert_eq!(text.len(), CONNECT_CODE_PREFIX.len() + 109);
        assert_eq!(ConnectCode::parse(&text).unwrap(), code);

        let mut damaged = text.into_bytes();
        let last = damaged.len() - 1;
        damaged[last] = if damaged[last] == b'a' { b'b' } else { b'a' };
        assert!(ConnectCode::parse(core::str::from_utf8(&damaged).unwrap()).is_err());
        assert!(ConnectCode::parse("KC2invalid").is_err());
    }

    #[test]
    fn locator_and_introduction_tokens_are_epoch_and_device_separated() {
        let capability = [0x33; 32];
        let locator_vector: [u8; 32] =
            hex::decode("094c28502a8fbc9a5a8a78798b989e9f809888b400e54fd090d1392fbd5cf30b")
                .unwrap()
                .try_into()
                .unwrap();
        let introduction_vector: [u8; 32] =
            hex::decode("dfc49fc8fefb36f6ec2722748e385787657977ff531851a692fc8d5e98ec8b9d")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(discovery_locator(&capability, 1), locator_vector);
        assert_eq!(
            discovery_introduction_token(&capability, &[1; 32], 8),
            introduction_vector
        );
        assert_ne!(
            discovery_locator(&capability, 1),
            discovery_locator(&capability, 2)
        );
        assert_ne!(
            discovery_introduction_token(&capability, &[1; 32], 8),
            discovery_introduction_token(&capability, &[2; 32], 8)
        );
        assert_ne!(
            discovery_introduction_token(&capability, &[1; 32], 8),
            discovery_introduction_token(&capability, &[1; 32], 9)
        );
    }

    #[test]
    fn fixed_record_round_trip_and_wrong_capability_fail_closed() {
        let mut rng = StdRng::seed_from_u64(0x3101);
        let (code, account, device, authority, ingress) = fixture(&mut rng);
        let epoch = discovery_epoch(NOW);
        let route = DiscoveryRoute {
            kind: DiscoveryRouteKind::IntroductionMailbox,
            value: b"/ip4/192.0.2.1/tcp/4001/p2p/example".to_vec(),
        };
        let sealed = seal_discovery_record(
            &code,
            epoch,
            1,
            NOW,
            account,
            authority,
            vec![ingress],
            vec![route.clone()],
            &device,
            &mut rng,
        )
        .unwrap();
        assert_eq!(sealed.len(), DISCOVERY_RECORD_SIZE);
        let opened = open_discovery_record(&code, epoch, &sealed, NOW).unwrap();
        assert_eq!(opened.routes, vec![route]);
        assert_eq!(opened.ingress.len(), 1);
        assert_ne!(opened.digest(), [0u8; 32]);

        let wrong = ConnectCode {
            identity_digest: code.identity_digest,
            capability: [0x99; 32],
        };
        assert!(open_discovery_record(&wrong, epoch, &sealed, NOW).is_err());
        assert!(open_discovery_record(&code, epoch + 1, &sealed, NOW).is_err());
    }

    #[test]
    fn record_clock_window_padding_and_signature_are_strict() {
        let mut rng = StdRng::seed_from_u64(0x3102);
        let (code, account, device, authority, ingress) = fixture(&mut rng);
        let epoch = discovery_epoch(NOW);
        let sealed = seal_discovery_record(
            &code,
            epoch,
            7,
            NOW,
            account,
            authority,
            vec![ingress],
            Vec::new(),
            &device,
            &mut rng,
        )
        .unwrap();
        assert!(
            open_discovery_record(&code, epoch, &sealed, discovery_epoch_valid_from(epoch)).is_ok()
        );
        assert!(open_discovery_record(
            &code,
            epoch,
            &sealed,
            discovery_epoch_valid_until(epoch).unwrap()
        )
        .is_ok());
        assert!(open_discovery_record(
            &code,
            epoch,
            &sealed,
            discovery_epoch_valid_from(epoch).saturating_sub(1)
        )
        .is_err());

        let mut corrupt = sealed;
        let middle = corrupt.len() / 2;
        corrupt[middle] ^= 1;
        assert!(open_discovery_record(&code, epoch, &corrupt, NOW).is_err());
    }
}
