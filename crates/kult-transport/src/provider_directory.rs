//! Signed, replaceable provider-directory policy for ADR-0017 operating modes.

use atomicwrites::{AllowOverwrite, AtomicFile};
use kult_crypto::verify_ed25519_domain_signature;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::path::Path;

use crate::internet::parse_addr;
use crate::{RendezvousProvider, MAX_RENDEZVOUS_PROVIDERS};

/// Current signed provider-directory document version.
pub const PROVIDER_DIRECTORY_VERSION: u8 = 1;
/// Maximum serialized directory or cache bytes accepted from disk.
const MAX_PROVIDER_DIRECTORY_FILE_BYTES: u64 = 256 * 1024;
/// Maximum trusted offline directory roots configured by one shell.
const MAX_TRUSTED_DIRECTORY_KEYS: usize = 8;
/// Maximum retained signing-key transition chain.
const MAX_PROVIDER_DIRECTORY_CHAIN: usize = 16;
/// Maximum operators in one directory.
const MAX_PROVIDER_OPERATORS: usize = 32;
/// Maximum entries for one operator and role.
const MAX_PROVIDER_ROLE_ENTRIES: usize = 8;
/// Maximum validity interval for one signed directory.
const MAX_PROVIDER_DIRECTORY_VALIDITY_SECS: u64 = 90 * 24 * 60 * 60;
/// A last-valid directory remains usable, visibly stale, for bounded outages.
const PROVIDER_DIRECTORY_STALE_GRACE_SECS: u64 = 30 * 24 * 60 * 60;
/// Small wall-clock tolerance for a freshly published directory.
const PROVIDER_DIRECTORY_CLOCK_SKEW_SECS: u64 = 24 * 60 * 60;
const DIRECTORY_SIGNATURE_DOMAIN: &[u8] = b"Komms-Provider-Directory-v1";

/// Canonical operating mode shared by daemon, FFI, and shells.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatingMode {
    /// Disclosed, replaceable convenience providers.
    #[default]
    Standard,
    /// Optional rendezvous goes through a configured Tor ingress.
    Private,
    /// Optional rendezvous and directory defaults are disabled.
    Sovereign,
}

/// One bounded HTTPS rendezvous provider advertised by an operator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRendezvous {
    /// Canonical HTTPS origin.
    pub origin: String,
    /// SHA-256 of the provider's leaf TLS certificate, lowercase hex.
    pub static_key: String,
    /// Direct HTTPS may be used by Standard mode.
    pub standard: bool,
    /// This endpoint is intended to be reached through Tor by Private mode.
    pub private_via_tor: bool,
}

/// One independently configurable operator and its least-authority roles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderOperator {
    /// Stable display-safe identifier, not a user or account identifier.
    pub operator_id: String,
    /// Disclosed administrative domain controlling these roles.
    pub administrative_domain: String,
    /// libp2p bootstrap/Kademlia cache multiaddresses.
    #[serde(default)]
    pub bootstrap: Vec<String>,
    /// libp2p circuit-relay multiaddresses.
    #[serde(default)]
    pub relays: Vec<String>,
    /// Durable mailbox-v2 multiaddresses.
    #[serde(default)]
    pub mailboxes: Vec<String>,
    /// Short-lived post-pairing rendezvous services.
    #[serde(default)]
    pub rendezvous: Vec<ProviderRendezvous>,
}

/// Human-editable signed provider-directory document.
///
/// Binary values use canonical lowercase hexadecimal. The signature covers a
/// deterministic binary encoding of all preceding fields, independent of JSON
/// whitespace or object-key order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderDirectory {
    /// Schema and canonical-signature version.
    pub version: u8,
    /// Strictly increasing directory generation.
    pub generation: u64,
    /// First Unix second at which this document is intended for use.
    pub valid_from: u64,
    /// Last Unix second at which this document is current.
    pub valid_until: u64,
    /// Digest of the complete preceding accepted document, lowercase hex.
    pub previous_digest: Option<String>,
    /// Exact Ed25519 key that signed this generation, lowercase hex.
    pub signing_key: String,
    /// Optional next offline signing key authorized by this generation.
    pub next_signing_key: Option<String>,
    /// First generation at which `next_signing_key` may sign.
    pub next_key_not_before_generation: Option<u64>,
    /// Sorted, unique operator records.
    pub operators: Vec<ProviderOperator>,
    /// Ed25519 signature over the canonical document, lowercase hex.
    pub signature: String,
}

/// Manual, user-controlled providers preserved independently of the directory.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ManualProviderSet {
    /// User-selected DHT bootstrap peers.
    pub bootstrap: Vec<String>,
    /// User-selected circuit relay.
    pub relay: Option<String>,
    /// User-selected mailbox relays.
    pub mailboxes: Vec<String>,
    /// User-selected rendezvous providers.
    pub rendezvous: Vec<ProviderRendezvous>,
}

/// Effective startup providers after mode policy is applied.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EffectiveProviderSet {
    /// Combined user and eligible directory bootstrap peers.
    pub bootstrap: Vec<String>,
    /// Preferred user or directory circuit relay.
    pub relay: Option<String>,
    /// Combined user and eligible directory mailboxes.
    pub mailboxes: Vec<String>,
    /// Eligible rendezvous providers; always empty in Sovereign mode.
    pub rendezvous: Vec<RendezvousProvider>,
}

/// How the selected provider directory was obtained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderDirectoryStatus {
    /// A current candidate was accepted or already cached.
    Current,
    /// A bad, conflicting, or unavailable candidate was ignored in favor of
    /// an unexpired last-valid document.
    RetainedLastValid,
    /// The bounded outage grace is active after directory expiry.
    Stale,
    /// Candidate or retained state conflicts with the authenticated chain.
    /// Directory defaults are disabled; manual and core routes remain.
    Conflict,
    /// No safely usable directory exists; manual and core routes still work.
    Unavailable,
}

/// Result of loading, verifying, caching, and applying one directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderDirectoryResolution {
    /// Selected directory, absent when no safe directory default is usable.
    pub directory: Option<ProviderDirectory>,
    /// Visible freshness/fallback state.
    pub status: ProviderDirectoryStatus,
    /// Effective provider set under the requested mode.
    pub providers: EffectiveProviderSet,
}

/// Provider-directory validation or persistence failure.
#[derive(Debug)]
pub enum ProviderDirectoryError {
    /// A configured path could not be read or durably replaced.
    Io(io::Error),
    /// JSON was malformed, oversized, or contained an unknown field.
    Encoding(String),
    /// A signature, chain, generation, time bound, or provider was invalid.
    Invalid(&'static str),
}

impl fmt::Display for ProviderDirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "provider directory I/O: {error}"),
            Self::Encoding(error) => write!(f, "provider directory encoding: {error}"),
            Self::Invalid(reason) => write!(f, "invalid provider directory: {reason}"),
        }
    }
}

impl std::error::Error for ProviderDirectoryError {}

impl From<io::Error> for ProviderDirectoryError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Clone)]
struct VerifiedDirectory {
    document: ProviderDirectory,
    signing_key: [u8; 32],
    next_signing_key: Option<[u8; 32]>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderDirectoryCache {
    version: u8,
    chain: Vec<ProviderDirectory>,
}

/// Resolve a candidate and retained cache without making a provider mandatory.
///
/// Invalid candidate data never replaces the cache. If the selected directory
/// exceeds its bounded stale grace, directory defaults are omitted while
/// manual DHT, mailbox, direct, LAN, mesh, and sneakernet routes remain intact.
pub fn resolve_provider_directory(
    mode: OperatingMode,
    candidate_path: Option<&Path>,
    cache_path: &Path,
    trusted_keys: &[[u8; 32]],
    manual: &ManualProviderSet,
    now: u64,
) -> Result<ProviderDirectoryResolution, ProviderDirectoryError> {
    validate_manual(manual)?;
    // An absent candidate path is an explicit local opt-out. Retained state is
    // only consulted while a directory remains configured; a configured path
    // that is temporarily unreadable still receives bounded last-valid
    // fallback below.
    if candidate_path.is_none() {
        return Ok(ProviderDirectoryResolution {
            directory: None,
            status: ProviderDirectoryStatus::Unavailable,
            providers: effective_providers(mode, None, manual)?,
        });
    }
    if trusted_keys.is_empty() {
        return Err(ProviderDirectoryError::Invalid(
            "directory data configured without a trusted root",
        ));
    }
    validate_trusted_keys(trusted_keys)?;

    let cache = match load_cache(cache_path) {
        Ok(cache) => cache,
        Err(_) => {
            return Ok(ProviderDirectoryResolution {
                directory: None,
                status: ProviderDirectoryStatus::Conflict,
                providers: effective_providers(mode, None, manual)?,
            });
        }
    };
    let mut verified_chain = match verify_chain(&cache.chain, trusted_keys) {
        Ok(chain) => chain,
        Err(_) => {
            return Ok(ProviderDirectoryResolution {
                directory: None,
                status: ProviderDirectoryStatus::Conflict,
                providers: effective_providers(mode, None, manual)?,
            });
        }
    };
    let had_usable_cache = !verified_chain.is_empty();
    let candidate = candidate_path.and_then(|path| load_document(path).ok());
    let mut accepted_candidate = false;
    let mut rejected_candidate = candidate_path.is_some() && candidate.is_none();

    if let Some(document) = candidate {
        match verify_successor(&document, verified_chain.last(), trusted_keys) {
            Ok(candidate) => {
                let already_current = verified_chain
                    .last()
                    .is_some_and(|current| current.digest == candidate.digest);
                if already_current {
                    accepted_candidate = true;
                } else if verified_chain.last().is_none_or(|current| {
                    candidate.document.generation > current.document.generation
                }) {
                    verified_chain.push(candidate);
                    if verified_chain.len() > MAX_PROVIDER_DIRECTORY_CHAIN {
                        return Err(ProviderDirectoryError::Invalid(
                            "signing-key transition chain exceeds the retained bound",
                        ));
                    }
                    write_cache(cache_path, &verified_chain)?;
                    accepted_candidate = true;
                } else {
                    rejected_candidate = true;
                }
            }
            Err(_) => rejected_candidate = true,
        }
    }

    let selected = verified_chain.iter().rev().find(|directory| {
        now.saturating_add(PROVIDER_DIRECTORY_CLOCK_SKEW_SECS) >= directory.document.valid_from
            && now
                <= directory
                    .document
                    .valid_until
                    .saturating_add(PROVIDER_DIRECTORY_STALE_GRACE_SECS)
    });
    let status = match selected {
        None if rejected_candidate => ProviderDirectoryStatus::Conflict,
        None => ProviderDirectoryStatus::Unavailable,
        Some(directory) if now > directory.document.valid_until => ProviderDirectoryStatus::Stale,
        Some(_) if rejected_candidate && had_usable_cache => {
            ProviderDirectoryStatus::RetainedLastValid
        }
        Some(directory)
            if (accepted_candidate
                && verified_chain
                    .last()
                    .is_some_and(|latest| latest.digest == directory.digest))
                || candidate_path.is_none() =>
        {
            ProviderDirectoryStatus::Current
        }
        Some(_) => ProviderDirectoryStatus::RetainedLastValid,
    };
    let directory = selected.map(|directory| directory.document.clone());
    let providers = effective_providers(mode, directory.as_ref(), manual)?;
    Ok(ProviderDirectoryResolution {
        directory,
        status,
        providers,
    })
}

fn load_document(path: &Path) -> Result<ProviderDirectory, ProviderDirectoryError> {
    let bytes = read_bounded(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| ProviderDirectoryError::Encoding(error.to_string()))
}

fn load_cache(path: &Path) -> Result<ProviderDirectoryCache, ProviderDirectoryError> {
    if !path.exists() {
        return Ok(ProviderDirectoryCache::default());
    }
    let bytes = read_bounded(path)?;
    let cache: ProviderDirectoryCache = serde_json::from_slice(&bytes)
        .map_err(|error| ProviderDirectoryError::Encoding(error.to_string()))?;
    if cache.version != PROVIDER_DIRECTORY_VERSION
        || cache.chain.len() > MAX_PROVIDER_DIRECTORY_CHAIN
    {
        return Err(ProviderDirectoryError::Invalid(
            "cache version or chain length",
        ));
    }
    Ok(cache)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, ProviderDirectoryError> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_PROVIDER_DIRECTORY_FILE_BYTES {
        return Err(ProviderDirectoryError::Invalid("file type or size"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_PROVIDER_DIRECTORY_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_PROVIDER_DIRECTORY_FILE_BYTES {
        return Err(ProviderDirectoryError::Invalid("file size"));
    }
    Ok(bytes)
}

fn write_cache(path: &Path, chain: &[VerifiedDirectory]) -> Result<(), ProviderDirectoryError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let cache = ProviderDirectoryCache {
        version: PROVIDER_DIRECTORY_VERSION,
        chain: chain.iter().map(|entry| entry.document.clone()).collect(),
    };
    let bytes = serde_json::to_vec_pretty(&cache)
        .map_err(|error| ProviderDirectoryError::Encoding(error.to_string()))?;
    if bytes.len() as u64 > MAX_PROVIDER_DIRECTORY_FILE_BYTES {
        return Err(ProviderDirectoryError::Invalid("cache size"));
    }
    AtomicFile::new(path, AllowOverwrite)
        .write(|file| {
            file.write_all(&bytes)?;
            file.sync_all()
        })
        .map_err(|error| match error {
            atomicwrites::Error::Internal(error) | atomicwrites::Error::User(error) => {
                ProviderDirectoryError::Io(error)
            }
        })?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn validate_trusted_keys(keys: &[[u8; 32]]) -> Result<(), ProviderDirectoryError> {
    if keys.is_empty() || keys.len() > MAX_TRUSTED_DIRECTORY_KEYS {
        return Err(ProviderDirectoryError::Invalid("trusted root count"));
    }
    let mut unique = HashSet::new();
    if keys
        .iter()
        .any(|key| *key == [0u8; 32] || !unique.insert(*key))
    {
        return Err(ProviderDirectoryError::Invalid("trusted root key"));
    }
    Ok(())
}

fn verify_chain(
    documents: &[ProviderDirectory],
    trusted_keys: &[[u8; 32]],
) -> Result<Vec<VerifiedDirectory>, ProviderDirectoryError> {
    if documents.len() > MAX_PROVIDER_DIRECTORY_CHAIN {
        return Err(ProviderDirectoryError::Invalid("cached chain length"));
    }
    let mut verified = Vec::with_capacity(documents.len());
    for document in documents {
        verified.push(verify_successor(document, verified.last(), trusted_keys)?);
    }
    Ok(verified)
}

fn verify_successor(
    document: &ProviderDirectory,
    previous: Option<&VerifiedDirectory>,
    trusted_keys: &[[u8; 32]],
) -> Result<VerifiedDirectory, ProviderDirectoryError> {
    let canonical = canonical_document(document)?;
    let signing_key = parse_hex::<32>(&document.signing_key)?;
    let signature = parse_hex::<64>(&document.signature)?;
    verify_ed25519_domain_signature(
        &signing_key,
        DIRECTORY_SIGNATURE_DOMAIN,
        &canonical,
        &signature,
    )
    .map_err(|_| ProviderDirectoryError::Invalid("signature"))?;

    match previous {
        None => {
            if document.previous_digest.is_some() || !trusted_keys.contains(&signing_key) {
                return Err(ProviderDirectoryError::Invalid("untrusted genesis"));
            }
        }
        Some(previous) => {
            if document.generation <= previous.document.generation
                || document.previous_digest.as_deref()
                    != Some(hex_string(&previous.digest).as_str())
            {
                return Err(ProviderDirectoryError::Invalid(
                    "rollback, fork, or missing parent binding",
                ));
            }
            let rotated = previous.next_signing_key.is_some_and(|key| {
                key == signing_key
                    && previous
                        .document
                        .next_key_not_before_generation
                        .is_some_and(|generation| document.generation >= generation)
            });
            if signing_key != previous.signing_key && !rotated {
                return Err(ProviderDirectoryError::Invalid(
                    "unauthorized signing-key transition",
                ));
            }
        }
    }

    let next_signing_key = document
        .next_signing_key
        .as_deref()
        .map(parse_hex::<32>)
        .transpose()?;
    let mut digest = Sha256::new();
    digest.update(&canonical);
    digest.update(signature);
    Ok(VerifiedDirectory {
        document: document.clone(),
        signing_key,
        next_signing_key,
        digest: digest.finalize().into(),
    })
}

fn canonical_document(document: &ProviderDirectory) -> Result<Vec<u8>, ProviderDirectoryError> {
    if document.version != PROVIDER_DIRECTORY_VERSION
        || document.generation == 0
        || document.valid_from > document.valid_until
        || document.valid_until.saturating_sub(document.valid_from)
            > MAX_PROVIDER_DIRECTORY_VALIDITY_SECS
        || document.operators.is_empty()
        || document.operators.len() > MAX_PROVIDER_OPERATORS
    {
        return Err(ProviderDirectoryError::Invalid(
            "version, generation, validity, or operator count",
        ));
    }
    let previous = document
        .previous_digest
        .as_deref()
        .map(parse_hex::<32>)
        .transpose()?;
    let signing = parse_hex::<32>(&document.signing_key)?;
    let next = document
        .next_signing_key
        .as_deref()
        .map(parse_hex::<32>)
        .transpose()?;
    if next.is_some() != document.next_key_not_before_generation.is_some()
        || document
            .next_key_not_before_generation
            .is_some_and(|generation| generation <= document.generation)
        || next == Some(signing)
    {
        return Err(ProviderDirectoryError::Invalid("next signing key"));
    }

    let mut out = Vec::new();
    out.extend_from_slice(b"KPD1");
    out.push(document.version);
    out.extend_from_slice(&document.generation.to_be_bytes());
    out.extend_from_slice(&document.valid_from.to_be_bytes());
    out.extend_from_slice(&document.valid_until.to_be_bytes());
    push_optional_fixed(&mut out, previous.as_ref());
    out.extend_from_slice(&signing);
    push_optional_fixed(&mut out, next.as_ref());
    out.extend_from_slice(
        &document
            .next_key_not_before_generation
            .unwrap_or(0)
            .to_be_bytes(),
    );
    push_u16(&mut out, document.operators.len())?;

    let mut prior_operator: Option<&str> = None;
    for operator in &document.operators {
        if !safe_id(&operator.operator_id)
            || !canonical_domain(&operator.administrative_domain)
            || prior_operator.is_some_and(|prior| prior >= operator.operator_id.as_str())
        {
            return Err(ProviderDirectoryError::Invalid(
                "operator identity or order",
            ));
        }
        prior_operator = Some(&operator.operator_id);
        push_string(&mut out, &operator.operator_id)?;
        push_string(&mut out, &operator.administrative_domain)?;
        canonical_role(&mut out, &operator.bootstrap)?;
        canonical_role(&mut out, &operator.relays)?;
        canonical_role(&mut out, &operator.mailboxes)?;
        if operator.rendezvous.len() > MAX_PROVIDER_ROLE_ENTRIES {
            return Err(ProviderDirectoryError::Invalid("rendezvous count"));
        }
        push_u16(&mut out, operator.rendezvous.len())?;
        let mut prior_rendezvous: Option<(&str, &str)> = None;
        for rendezvous in &operator.rendezvous {
            let provider = RendezvousProvider::new(
                rendezvous.origin.clone(),
                parse_hex::<32>(&rendezvous.static_key)?,
            )
            .map_err(|_| ProviderDirectoryError::Invalid("rendezvous provider"))?;
            if (!rendezvous.standard && !rendezvous.private_via_tor)
                || prior_rendezvous.is_some_and(|prior| {
                    prior >= (rendezvous.origin.as_str(), rendezvous.static_key.as_str())
                })
            {
                return Err(ProviderDirectoryError::Invalid(
                    "rendezvous access or order",
                ));
            }
            prior_rendezvous = Some((rendezvous.origin.as_str(), rendezvous.static_key.as_str()));
            push_string(&mut out, provider.origin())?;
            out.extend_from_slice(&provider.static_key());
            out.push(u8::from(rendezvous.standard));
            out.push(u8::from(rendezvous.private_via_tor));
        }
    }
    Ok(out)
}

fn canonical_role(out: &mut Vec<u8>, entries: &[String]) -> Result<(), ProviderDirectoryError> {
    if entries.len() > MAX_PROVIDER_ROLE_ENTRIES {
        return Err(ProviderDirectoryError::Invalid("provider role count"));
    }
    push_u16(out, entries.len())?;
    let mut prior: Option<&str> = None;
    for entry in entries {
        if prior.is_some_and(|value| value >= entry.as_str()) || parse_addr(entry).is_none() {
            return Err(ProviderDirectoryError::Invalid(
                "provider multiaddress or order",
            ));
        }
        prior = Some(entry);
        push_string(out, entry)?;
    }
    Ok(())
}

fn effective_providers(
    mode: OperatingMode,
    directory: Option<&ProviderDirectory>,
    manual: &ManualProviderSet,
) -> Result<EffectiveProviderSet, ProviderDirectoryError> {
    let mut bootstrap = manual.bootstrap.clone();
    let mut relays = manual.relay.clone().into_iter().collect::<Vec<_>>();
    let mut mailboxes = manual.mailboxes.clone();
    let mut rendezvous = manual.rendezvous.clone();

    if mode != OperatingMode::Sovereign {
        if let Some(directory) = directory {
            for operator in &directory.operators {
                bootstrap.extend(operator.bootstrap.iter().cloned());
                relays.extend(operator.relays.iter().cloned());
                mailboxes.extend(operator.mailboxes.iter().cloned());
                rendezvous.extend(operator.rendezvous.iter().cloned());
            }
        }
    }
    dedup_preserving_order(&mut bootstrap);
    dedup_preserving_order(&mut relays);
    dedup_preserving_order(&mut mailboxes);
    let rendezvous = if mode == OperatingMode::Sovereign {
        Vec::new()
    } else {
        let mut resolved = Vec::new();
        let mut ids = HashSet::new();
        for entry in rendezvous {
            let eligible = match mode {
                OperatingMode::Standard => entry.standard,
                OperatingMode::Private => entry.private_via_tor,
                OperatingMode::Sovereign => false,
            };
            if !eligible {
                continue;
            }
            let provider =
                RendezvousProvider::new(entry.origin, parse_hex::<32>(&entry.static_key)?)
                    .map_err(|_| ProviderDirectoryError::Invalid("rendezvous provider"))?;
            if ids.insert(provider.provider_id()) {
                if resolved.len() == MAX_RENDEZVOUS_PROVIDERS {
                    break;
                }
                resolved.push(provider);
            }
        }
        resolved
    };
    Ok(EffectiveProviderSet {
        bootstrap,
        relay: relays.into_iter().next(),
        mailboxes,
        rendezvous,
    })
}

fn validate_manual(manual: &ManualProviderSet) -> Result<(), ProviderDirectoryError> {
    if manual.bootstrap.len() > MAX_PROVIDER_OPERATORS * MAX_PROVIDER_ROLE_ENTRIES
        || manual.mailboxes.len() > MAX_PROVIDER_OPERATORS * MAX_PROVIDER_ROLE_ENTRIES
        || manual.rendezvous.len() > MAX_RENDEZVOUS_PROVIDERS
        || manual
            .bootstrap
            .iter()
            .any(|entry| parse_addr(entry).is_none())
        || manual
            .relay
            .as_ref()
            .is_some_and(|entry| parse_addr(entry).is_none())
        || manual
            .mailboxes
            .iter()
            .any(|entry| parse_addr(entry).is_none())
    {
        return Err(ProviderDirectoryError::Invalid("manual provider set"));
    }
    for entry in &manual.rendezvous {
        if (!entry.standard && !entry.private_via_tor)
            || RendezvousProvider::new(entry.origin.clone(), parse_hex::<32>(&entry.static_key)?)
                .is_err()
        {
            return Err(ProviderDirectoryError::Invalid(
                "manual rendezvous provider",
            ));
        }
    }
    Ok(())
}

fn dedup_preserving_order(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

fn parse_hex<const N: usize>(value: &str) -> Result<[u8; N], ProviderDirectoryError> {
    if value.len() != N * 2
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(ProviderDirectoryError::Invalid("non-canonical hexadecimal"));
    }
    let mut out = [0u8; N];
    for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        out[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(out)
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}

fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn push_optional_fixed<const N: usize>(out: &mut Vec<u8>, value: Option<&[u8; N]>) {
    out.push(u8::from(value.is_some()));
    if let Some(value) = value {
        out.extend_from_slice(value);
    }
}

fn push_u16(out: &mut Vec<u8>, value: usize) -> Result<(), ProviderDirectoryError> {
    let value = u16::try_from(value)
        .map_err(|_| ProviderDirectoryError::Invalid("canonical count overflow"))?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn push_string(out: &mut Vec<u8>, value: &str) -> Result<(), ProviderDirectoryError> {
    push_u16(out, value.len())?;
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !value.ends_with('-')
}

fn canonical_domain(value: &str) -> bool {
    if value.len() > 253 || value.parse::<IpAddr>().is_ok() {
        return false;
    }
    let labels = value.split('.').collect::<Vec<_>>();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::OsRng;
    use tempfile::tempdir;

    fn provider(operator: &str) -> ProviderOperator {
        let host = if operator == "alpha" {
            "192.0.2.1"
        } else {
            "192.0.2.2"
        };
        ProviderOperator {
            operator_id: operator.into(),
            administrative_domain: format!("{operator}.example"),
            bootstrap: vec![format!(
                "/ip4/{host}/tcp/443/p2p/12D3KooWBTZ16AqmT26j7fCY9WAeoV4XsnpxcqBsxzVPBgJdWya7"
            )],
            relays: Vec::new(),
            mailboxes: Vec::new(),
            rendezvous: vec![ProviderRendezvous {
                origin: format!("https://rv.{operator}.example"),
                static_key: hex_string(&[2u8; 32]),
                standard: true,
                private_via_tor: true,
            }],
        }
    }

    fn signed(
        key: &SigningKey,
        generation: u64,
        previous_digest: Option<String>,
        next: Option<(&SigningKey, u64)>,
    ) -> ProviderDirectory {
        signed_with_operators(
            key,
            generation,
            previous_digest,
            next,
            vec![provider("alpha")],
        )
    }

    fn signed_with_operators(
        key: &SigningKey,
        generation: u64,
        previous_digest: Option<String>,
        next: Option<(&SigningKey, u64)>,
        operators: Vec<ProviderOperator>,
    ) -> ProviderDirectory {
        let mut document = ProviderDirectory {
            version: PROVIDER_DIRECTORY_VERSION,
            generation,
            valid_from: 1_000,
            valid_until: 2_000,
            previous_digest,
            signing_key: hex_string(&key.verifying_key().to_bytes()),
            next_signing_key: next.map(|(key, _)| hex_string(&key.verifying_key().to_bytes())),
            next_key_not_before_generation: next.map(|(_, generation)| generation),
            operators,
            signature: String::new(),
        };
        let canonical = canonical_document(&document).unwrap();
        let mut message = Vec::from(DIRECTORY_SIGNATURE_DOMAIN);
        message.extend_from_slice(&canonical);
        document.signature = hex_string(&key.sign(&message).to_bytes());
        document
    }

    fn digest(document: &ProviderDirectory) -> String {
        hex_string(
            &verify_successor(document, None, &[parse_hex(&document.signing_key).unwrap()])
                .unwrap()
                .digest,
        )
    }

    fn write_document(path: &Path, document: &ProviderDirectory) {
        fs::write(path, serde_json::to_vec_pretty(document).unwrap()).unwrap();
    }

    #[test]
    fn accepts_signed_directory_and_applies_modes_without_erasing_manual_routes() {
        let root = SigningKey::generate(&mut OsRng);
        let directory = signed(&root, 1, None, None);
        let temp = tempdir().unwrap();
        let candidate = temp.path().join("candidate.json");
        let cache = temp.path().join("cache.json");
        write_document(&candidate, &directory);
        let manual = ManualProviderSet {
            bootstrap: vec![
                "/ip4/198.51.100.1/tcp/443/p2p/12D3KooWLFnPTnPQ7QgWT8CtctinEPduQPqV9F11ycRhPvhsqwH4"
                    .into(),
            ],
            ..ManualProviderSet::default()
        };
        let roots = [root.verifying_key().to_bytes()];

        let standard = resolve_provider_directory(
            OperatingMode::Standard,
            Some(&candidate),
            &cache,
            &roots,
            &manual,
            1_500,
        )
        .unwrap();
        assert_eq!(standard.status, ProviderDirectoryStatus::Current);
        assert_eq!(standard.providers.bootstrap.len(), 2);
        assert_eq!(standard.providers.rendezvous.len(), 1);

        let sovereign = resolve_provider_directory(
            OperatingMode::Sovereign,
            None,
            &cache,
            &roots,
            &manual,
            1_500,
        )
        .unwrap();
        assert_eq!(sovereign.providers.bootstrap, manual.bootstrap);
        assert!(sovereign.providers.rendezvous.is_empty());
    }

    #[test]
    fn retains_last_valid_on_fork_then_expires_after_bounded_grace() {
        let root = SigningKey::generate(&mut OsRng);
        let accepted = signed(&root, 1, None, None);
        let temp = tempdir().unwrap();
        let candidate = temp.path().join("candidate.json");
        let cache = temp.path().join("cache.json");
        write_document(&candidate, &accepted);
        let roots = [root.verifying_key().to_bytes()];
        resolve_provider_directory(
            OperatingMode::Standard,
            Some(&candidate),
            &cache,
            &roots,
            &ManualProviderSet::default(),
            1_500,
        )
        .unwrap();

        let fork = signed(&root, 2, Some(hex_string(&[9u8; 32])), None);
        write_document(&candidate, &fork);
        let retained = resolve_provider_directory(
            OperatingMode::Standard,
            Some(&candidate),
            &cache,
            &roots,
            &ManualProviderSet::default(),
            1_600,
        )
        .unwrap();
        assert_eq!(retained.status, ProviderDirectoryStatus::RetainedLastValid);
        assert_eq!(retained.directory.unwrap().generation, 1);

        let conflicted = resolve_provider_directory(
            OperatingMode::Standard,
            Some(&candidate),
            &cache,
            &roots,
            &ManualProviderSet::default(),
            2_001 + PROVIDER_DIRECTORY_STALE_GRACE_SECS,
        )
        .unwrap();
        assert_eq!(conflicted.status, ProviderDirectoryStatus::Conflict);
        assert!(conflicted.directory.is_none());
    }

    #[test]
    fn signing_key_rotation_requires_parent_authorization_and_activation() {
        let root = SigningKey::generate(&mut OsRng);
        let next = SigningKey::generate(&mut OsRng);
        let first = signed(&root, 1, None, Some((&next, 3)));
        let parent_digest = digest(&first);
        let early = signed(&next, 2, Some(parent_digest.clone()), None);
        let first_verified =
            verify_successor(&first, None, &[root.verifying_key().to_bytes()]).unwrap();
        assert!(verify_successor(&early, Some(&first_verified), &[]).is_err());
        let rotated = signed(&next, 3, Some(parent_digest), None);
        assert!(verify_successor(&rotated, Some(&first_verified), &[]).is_ok());
    }

    #[test]
    fn rejects_noncanonical_or_oversized_directory_inputs() {
        let key = SigningKey::generate(&mut OsRng);
        let mut document = signed(&key, 1, None, None);
        document.signing_key.make_ascii_uppercase();
        assert!(canonical_document(&document).is_err());

        let temp = tempdir().unwrap();
        let path = temp.path().join("large.json");
        fs::write(
            &path,
            vec![b'x'; MAX_PROVIDER_DIRECTORY_FILE_BYTES as usize + 1],
        )
        .unwrap();
        assert!(load_document(&path).is_err());
    }

    #[test]
    fn corrupt_retained_cache_cannot_be_replaced_as_fresh_genesis() {
        let root = SigningKey::generate(&mut OsRng);
        let old_genesis = signed(&root, 1, None, None);
        let temp = tempdir().unwrap();
        let candidate = temp.path().join("candidate.json");
        let cache = temp.path().join("cache.json");
        write_document(&candidate, &old_genesis);
        fs::write(&cache, b"{\"version\":1,\"chain\":[").unwrap();
        let manual = ManualProviderSet {
            bootstrap: vec![
                "/ip4/198.51.100.1/tcp/443/p2p/12D3KooWLFnPTnPQ7QgWT8CtctinEPduQPqV9F11ycRhPvhsqwH4"
                    .into(),
            ],
            ..ManualProviderSet::default()
        };

        let resolution = resolve_provider_directory(
            OperatingMode::Standard,
            Some(&candidate),
            &cache,
            &[root.verifying_key().to_bytes()],
            &manual,
            1_500,
        )
        .unwrap();

        assert_eq!(resolution.status, ProviderDirectoryStatus::Conflict);
        assert!(resolution.directory.is_none());
        assert_eq!(resolution.providers.bootstrap, manual.bootstrap);
        assert_eq!(fs::read(&cache).unwrap(), b"{\"version\":1,\"chain\":[");
    }

    #[test]
    fn removing_directory_configuration_disables_cached_defaults_without_erasing_manual_routes() {
        let root = SigningKey::generate(&mut OsRng);
        let directory = signed(&root, 1, None, None);
        let temp = tempdir().unwrap();
        let candidate = temp.path().join("candidate.json");
        let cache = temp.path().join("cache.json");
        write_document(&candidate, &directory);
        let manual = ManualProviderSet {
            bootstrap: vec![
                "/ip4/198.51.100.1/tcp/443/p2p/12D3KooWLFnPTnPQ7QgWT8CtctinEPduQPqV9F11ycRhPvhsqwH4"
                    .into(),
            ],
            ..ManualProviderSet::default()
        };
        let roots = [root.verifying_key().to_bytes()];

        let configured = resolve_provider_directory(
            OperatingMode::Standard,
            Some(&candidate),
            &cache,
            &roots,
            &manual,
            1_500,
        )
        .unwrap();
        assert_eq!(configured.providers.bootstrap.len(), 2);
        let retained_bytes = fs::read(&cache).unwrap();

        let disabled =
            resolve_provider_directory(OperatingMode::Standard, None, &cache, &[], &manual, 1_500)
                .unwrap();
        assert_eq!(disabled.status, ProviderDirectoryStatus::Unavailable);
        assert!(disabled.directory.is_none());
        assert_eq!(disabled.providers.bootstrap, manual.bootstrap);
        assert!(disabled.providers.rendezvous.is_empty());
        assert_eq!(fs::read(&cache).unwrap(), retained_bytes);
    }

    #[test]
    fn deterministic_clean_install_provider_journeys_remain_replaceable_and_optional() {
        // This is a hermetic configuration/blackhole simulation, not field
        // qualification for distinct real NATs or an external operator.
        let root = SigningKey::generate(&mut OsRng);
        let first = signed(&root, 1, None, None);
        let first_digest = digest(&first);
        let temp = tempdir().unwrap();
        let candidate = temp.path().join("candidate.json");
        let missing_default = temp.path().join("default-blackhole.json");
        let cache = temp.path().join("cache.json");
        write_document(&candidate, &first);
        let manual = ManualProviderSet {
            bootstrap: vec![
                "/ip4/198.51.100.1/tcp/443/p2p/12D3KooWLFnPTnPQ7QgWT8CtctinEPduQPqV9F11ycRhPvhsqwH4"
                    .into(),
            ],
            mailboxes: vec![
                "/ip4/198.51.100.2/tcp/443/p2p/12D3KooWLFnPTnPQ7QgWT8CtctinEPduQPqV9F11ycRhPvhsqwH4"
                    .into(),
            ],
            ..ManualProviderSet::default()
        };
        let roots = [root.verifying_key().to_bytes()];

        let standard = resolve_provider_directory(
            OperatingMode::Standard,
            Some(&candidate),
            &cache,
            &roots,
            &manual,
            1_500,
        )
        .unwrap();
        assert_eq!(standard.status, ProviderDirectoryStatus::Current);
        assert_eq!(standard.providers.bootstrap.len(), 2);
        assert_eq!(standard.providers.bootstrap[0], manual.bootstrap[0]);

        let blackholed = resolve_provider_directory(
            OperatingMode::Standard,
            Some(&missing_default),
            &cache,
            &roots,
            &manual,
            1_600,
        )
        .unwrap();
        assert_eq!(
            blackholed.status,
            ProviderDirectoryStatus::RetainedLastValid
        );
        assert_eq!(blackholed.providers.bootstrap, standard.providers.bootstrap);

        let replacement =
            signed_with_operators(&root, 2, Some(first_digest), None, vec![provider("beta")]);
        write_document(&candidate, &replacement);
        let replaced = resolve_provider_directory(
            OperatingMode::Standard,
            Some(&candidate),
            &cache,
            &roots,
            &manual,
            1_700,
        )
        .unwrap();
        assert_eq!(replaced.directory.unwrap().generation, 2);
        assert!(replaced
            .providers
            .bootstrap
            .iter()
            .any(|address| address.contains("192.0.2.2")));
        assert!(!replaced
            .providers
            .bootstrap
            .iter()
            .any(|address| address.contains("192.0.2.1")));
        assert_eq!(replaced.providers.bootstrap[0], manual.bootstrap[0]);

        let pure_core_cache = temp.path().join("pure-core-cache.json");
        let pure_core = resolve_provider_directory(
            OperatingMode::Sovereign,
            None,
            &pure_core_cache,
            &[],
            &manual,
            1_700,
        )
        .unwrap();
        assert_eq!(pure_core.status, ProviderDirectoryStatus::Unavailable);
        assert_eq!(pure_core.providers.bootstrap, manual.bootstrap);
        assert_eq!(pure_core.providers.mailboxes, manual.mailboxes);
        assert!(pure_core.providers.rendezvous.is_empty());
    }

    #[test]
    fn directory_defaults_never_displace_bounded_manual_rendezvous() {
        let key = SigningKey::generate(&mut OsRng);
        let directory = signed(&key, 1, None, None);
        let manual = ManualProviderSet {
            rendezvous: (0..MAX_RENDEZVOUS_PROVIDERS)
                .map(|index| ProviderRendezvous {
                    origin: format!("https://manual-{index}.example"),
                    static_key: hex_string(&[index as u8 + 1; 32]),
                    standard: true,
                    private_via_tor: true,
                })
                .collect(),
            ..ManualProviderSet::default()
        };

        let effective =
            effective_providers(OperatingMode::Standard, Some(&directory), &manual).unwrap();
        assert_eq!(effective.rendezvous.len(), MAX_RENDEZVOUS_PROVIDERS);
        assert!(effective
            .rendezvous
            .iter()
            .all(|provider| provider.origin().starts_with("https://manual-")));
    }
}
