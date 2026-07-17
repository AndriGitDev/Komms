//! Bounded deterministic C2 linked-device state synchronization.
//!
//! Mutations are signed by certified physical-device keys and converge by a
//! total LWW order per `(namespace, key)`. Encrypted bundles are strictly a
//! proximate peer-to-peer/LAN/file mechanism: there is no account server or
//! cloud log. Ratchets, sender chains, drafts, downloaded media, and screen
//! settings are intentionally absent from the synchronized namespaces.

use alloc::{collections::BTreeMap, vec::Vec};

use kult_crypto::{DeviceManifest, Identity, StorageKey};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ProtocolError, Result};

const SYNC_BUNDLE_AD: &[u8] = b"Komms-device-sync-bundle-v1";
/// Maximum logical sync mutations in one encrypted transfer.
pub const MAX_DEVICE_SYNC_BUNDLE_EVENTS: usize = 4_096;
/// Maximum encoded encrypted sync bundle bytes.
pub const MAX_DEVICE_SYNC_BUNDLE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum logical sync key bytes.
pub const MAX_DEVICE_SYNC_KEY_BYTES: usize = 512;
/// Maximum mutation value bytes.
pub const MAX_DEVICE_SYNC_VALUE_BYTES: usize = 1024 * 1024;

/// Synchronized state classes with explicit product semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DeviceSyncNamespace {
    /// Contact records and private petnames.
    Contacts,
    /// Safety-number verification state.
    Verification,
    /// Folders, labels, pins, icons, and shared appearance preference.
    LocalOrganization,
    /// Ordinary pairwise/group/note history delivered to another device.
    ConversationHistory,
    /// Group definitions and signed authority state, never live sender keys.
    Groups,
    /// Immutable authenticated pairwise/group edit events.
    MessageEdits,
    /// Immutable group poll events and resolved closure snapshots.
    GroupPolls,
    /// Terminal consumed/expired tombstones only, never ephemeral plaintext.
    ExpiryTombstones,
}

/// One signed state mutation from one exact certified physical device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSyncEvent {
    /// Stable account identity.
    pub account: [u8; 32],
    /// Authoring physical-device id.
    pub author_device: [u8; 32],
    /// Strictly increasing author-local counter.
    pub counter: u64,
    /// Lamport time used before deterministic author/id tie-breaks.
    pub lamport: u64,
    /// Manifest generation known when this event was authored.
    pub manifest_generation: u64,
    /// Explicit synchronized state class.
    pub namespace: DeviceSyncNamespace,
    /// Canonical application-owned stable key.
    pub key: Vec<u8>,
    /// Replacement bytes, or `None` for a permanent logical tombstone.
    pub value: Option<Vec<u8>>,
    /// Physical-device signature over every preceding field.
    #[serde(with = "bytes64")]
    pub signature: [u8; 64],
}

impl DeviceSyncEvent {
    /// Create one signed bounded mutation.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        account: [u8; 32],
        device: &Identity,
        counter: u64,
        lamport: u64,
        manifest_generation: u64,
        namespace: DeviceSyncNamespace,
        key: Vec<u8>,
        value: Option<Vec<u8>>,
    ) -> Result<Self> {
        let mut event = Self {
            account,
            author_device: device.public().ed,
            counter,
            lamport,
            manifest_generation,
            namespace,
            key,
            value,
            signature: [0u8; 64],
        };
        event.validate_bounds()?;
        event.signature = device.sign_device_sync_event(&event.canonical());
        Ok(event)
    }

    /// Stable digest for deduplication and final convergence tie-breaking.
    pub fn event_id(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(self.canonical());
        hash.update(self.signature);
        hash.finalize().into()
    }

    /// Encode one exact event for independently sealed store retention.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate_bounds()?;
        postcard::to_allocvec(self).map_err(|_| ProtocolError::Malformed)
    }

    /// Strictly decode one bounded event.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_DEVICE_SYNC_VALUE_BYTES + MAX_DEVICE_SYNC_KEY_BYTES + 256 {
            return Err(ProtocolError::TooLarge);
        }
        let (event, remainder): (Self, &[u8]) =
            postcard::take_from_bytes(bytes).map_err(|_| ProtocolError::Malformed)?;
        if !remainder.is_empty() {
            return Err(ProtocolError::Malformed);
        }
        event.validate_bounds()?;
        Ok(event)
    }

    /// Verify account/device authorization and the revocation counter cutoff.
    pub fn verify(&self, manifest: &DeviceManifest) -> Result<()> {
        self.validate_bounds()?;
        manifest.verify().map_err(|_| ProtocolError::Malformed)?;
        if self.account != manifest.account.ed || self.manifest_generation > manifest.generation {
            return Err(ProtocolError::Malformed);
        }
        let entry = manifest
            .devices
            .iter()
            .find(|entry| entry.certificate.device_id() == self.author_device)
            .ok_or(ProtocolError::Malformed)?;
        if entry
            .revoked_after_counter
            .is_some_and(|cutoff| self.counter > cutoff)
        {
            return Err(ProtocolError::Malformed);
        }
        entry
            .certificate
            .device
            .verify_device_sync_event(&self.canonical(), &self.signature)
            .map_err(|_| ProtocolError::Malformed)
    }

    fn validate_bounds(&self) -> Result<()> {
        if self.account == [0u8; 32]
            || self.author_device == [0u8; 32]
            || self.counter == 0
            || self.lamport == 0
            || self.manifest_generation == 0
            || self.key.is_empty()
            || self.key.len() > MAX_DEVICE_SYNC_KEY_BYTES
            || self
                .value
                .as_ref()
                .is_some_and(|value| value.len() > MAX_DEVICE_SYNC_VALUE_BYTES)
        {
            return Err(ProtocolError::Malformed);
        }
        Ok(())
    }

    fn canonical(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            32 + 32 + 8 * 3 + 1 + 4 + self.key.len() + 5 + self.value.as_ref().map_or(0, Vec::len),
        );
        out.extend_from_slice(&self.account);
        out.extend_from_slice(&self.author_device);
        out.extend_from_slice(&self.counter.to_le_bytes());
        out.extend_from_slice(&self.lamport.to_le_bytes());
        out.extend_from_slice(&self.manifest_generation.to_le_bytes());
        out.push(self.namespace as u8);
        out.extend_from_slice(&(self.key.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.key);
        match &self.value {
            Some(value) => {
                out.push(1);
                out.extend_from_slice(&(value.len() as u32).to_le_bytes());
                out.extend_from_slice(value);
            }
            None => out.push(0),
        }
        out
    }
}

/// Deterministically resolve all valid events to one winner per logical key.
pub fn resolve_device_sync_events(
    manifest: &DeviceManifest,
    events: impl IntoIterator<Item = DeviceSyncEvent>,
) -> BTreeMap<(DeviceSyncNamespace, Vec<u8>), DeviceSyncEvent> {
    let mut resolved = BTreeMap::new();
    for event in events {
        if event.verify(manifest).is_err() {
            continue;
        }
        let key = (event.namespace, event.key.clone());
        let order = |candidate: &DeviceSyncEvent| {
            (
                candidate.lamport,
                candidate.author_device,
                candidate.counter,
                candidate.event_id(),
            )
        };
        if resolved
            .get(&key)
            .is_none_or(|current| order(&event) > order(current))
        {
            resolved.insert(key, event);
        }
    }
    resolved
}

/// Minimal outer header for one channel-encrypted sync bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSyncBundle {
    /// Sending physical-device id.
    pub sender: [u8; 32],
    /// Exact intended receiving physical-device id.
    pub recipient: [u8; 32],
    /// Strictly increasing pairwise channel sequence.
    pub sequence: u64,
    /// AEAD-sealed manifest and event set.
    pub sealed: Vec<u8>,
}

/// Authenticated bundle contents returned only after complete validation.
pub struct OpenedDeviceSyncBundle {
    /// Latest authority state carried by the sender.
    pub manifest: DeviceManifest,
    /// Valid signed events in encoded order.
    pub events: Vec<DeviceSyncEvent>,
}

#[derive(Serialize, Deserialize)]
struct DeviceSyncPayload {
    manifest: DeviceManifest,
    events: Vec<DeviceSyncEvent>,
}

impl DeviceSyncBundle {
    /// Seal a bounded manifest and event set to one exact linked peer.
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        channel_root: &[u8; 32],
        sender: [u8; 32],
        recipient: [u8; 32],
        sequence: u64,
        manifest: DeviceManifest,
        events: Vec<DeviceSyncEvent>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        if sender == recipient || sequence == 0 || events.len() > MAX_DEVICE_SYNC_BUNDLE_EVENTS {
            return Err(ProtocolError::Malformed);
        }
        manifest.verify().map_err(|_| ProtocolError::Malformed)?;
        if !manifest
            .devices
            .iter()
            .any(|entry| entry.certificate.device_id() == sender && entry.revoked_at.is_none())
            || !manifest
                .devices
                .iter()
                .any(|entry| entry.certificate.device_id() == recipient)
        {
            return Err(ProtocolError::Malformed);
        }
        for event in &events {
            event.verify(&manifest)?;
        }
        let payload = DeviceSyncPayload { manifest, events };
        let plain = postcard::to_allocvec(&payload).map_err(|_| ProtocolError::Malformed)?;
        if plain.len() > MAX_DEVICE_SYNC_BUNDLE_BYTES {
            return Err(ProtocolError::TooLarge);
        }
        let ad = bundle_ad(sender, recipient, sequence);
        let sealed = StorageKey::from_bytes(*channel_root).seal(&ad, &plain, rng);
        Ok(Self {
            sender,
            recipient,
            sequence,
            sealed,
        })
    }

    /// Encode for a proximate LAN/file transfer.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let bytes = postcard::to_allocvec(self).map_err(|_| ProtocolError::Malformed)?;
        if bytes.len() > MAX_DEVICE_SYNC_BUNDLE_BYTES + 256 {
            return Err(ProtocolError::TooLarge);
        }
        Ok(bytes)
    }

    /// Strictly decode the outer bounded header.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_DEVICE_SYNC_BUNDLE_BYTES + 256 {
            return Err(ProtocolError::TooLarge);
        }
        let (bundle, remainder): (Self, &[u8]) =
            postcard::take_from_bytes(bytes).map_err(|_| ProtocolError::Malformed)?;
        if !remainder.is_empty()
            || bundle.sender == bundle.recipient
            || bundle.sequence == 0
            || bundle.sealed.len() > MAX_DEVICE_SYNC_BUNDLE_BYTES + 64
        {
            return Err(ProtocolError::Malformed);
        }
        Ok(bundle)
    }

    /// Authenticate, decrypt, and validate every nested authority/event row.
    pub fn open(
        &self,
        channel_root: &[u8; 32],
        local_device: &[u8; 32],
        expected_sender: &[u8; 32],
    ) -> Result<OpenedDeviceSyncBundle> {
        if &self.recipient != local_device || &self.sender != expected_sender {
            return Err(ProtocolError::Malformed);
        }
        let ad = bundle_ad(self.sender, self.recipient, self.sequence);
        let plain = StorageKey::from_bytes(*channel_root)
            .open(&ad, &self.sealed)
            .map_err(|_| ProtocolError::Malformed)?;
        if plain.len() > MAX_DEVICE_SYNC_BUNDLE_BYTES {
            return Err(ProtocolError::TooLarge);
        }
        let (payload, remainder): (DeviceSyncPayload, &[u8]) =
            postcard::take_from_bytes(&plain).map_err(|_| ProtocolError::Malformed)?;
        if !remainder.is_empty() || payload.events.len() > MAX_DEVICE_SYNC_BUNDLE_EVENTS {
            return Err(ProtocolError::Malformed);
        }
        payload
            .manifest
            .verify()
            .map_err(|_| ProtocolError::Malformed)?;
        for event in &payload.events {
            event.verify(&payload.manifest)?;
        }
        Ok(OpenedDeviceSyncBundle {
            manifest: payload.manifest,
            events: payload.events,
        })
    }
}

fn bundle_ad(sender: [u8; 32], recipient: [u8; 32], sequence: u64) -> Vec<u8> {
    let mut ad = Vec::with_capacity(SYNC_BUNDLE_AD.len() + 72);
    ad.extend_from_slice(SYNC_BUNDLE_AD);
    ad.extend_from_slice(&sender);
    ad.extend_from_slice(&recipient);
    ad.extend_from_slice(&sequence.to_le_bytes());
    ad
}

mod bytes64 {
    use core::fmt;
    use serde::{de, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        value: &[u8; 64],
        serializer: S,
    ) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> core::result::Result<[u8; 64], D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = [u8; 64];

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("64 bytes")
            }

            fn visit_bytes<E: de::Error>(
                self,
                value: &[u8],
            ) -> core::result::Result<Self::Value, E> {
                value
                    .try_into()
                    .map_err(|_| E::invalid_length(value.len(), &self))
            }

            fn visit_seq<A: de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> core::result::Result<Self::Value, A::Error> {
                let mut out = [0u8; 64];
                for (index, slot) in out.iter_mut().enumerate() {
                    *slot = sequence
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(index, &self))?;
                }
                Ok(out)
            }
        }
        deserializer.deserialize_bytes(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kult_crypto::{DeviceCertificate, DeviceManifestEntry};
    use rand::{rngs::StdRng, SeedableRng};

    fn fixture() -> (Identity, Identity, Identity, DeviceManifest, StdRng) {
        let mut rng = StdRng::seed_from_u64(81);
        let account = Identity::generate(&mut rng);
        let first = Identity::generate(&mut rng);
        let second = Identity::generate(&mut rng);
        let first_cert = DeviceCertificate::issue(&account, &first, 10, &mut rng);
        let mut manifest =
            DeviceManifest::initial(&account, first_cert, "Phone".into(), 10).unwrap();
        let second_cert = DeviceCertificate::issue(&account, &second, 11, &mut rng);
        manifest
            .add_device(
                &account,
                DeviceManifestEntry {
                    certificate: second_cert,
                    name: "Laptop".into(),
                    last_seen: 11,
                    revoked_at: None,
                    revoked_after_counter: None,
                },
            )
            .unwrap();
        (account, first, second, manifest, rng)
    }

    #[test]
    fn events_converge_across_reorder_and_tombstones() {
        let (account, first, second, manifest, _) = fixture();
        let older = DeviceSyncEvent::sign(
            account.public().ed,
            &first,
            1,
            4,
            manifest.generation,
            DeviceSyncNamespace::Contacts,
            b"alice".to_vec(),
            Some(b"Alice".to_vec()),
        )
        .unwrap();
        let newer = DeviceSyncEvent::sign(
            account.public().ed,
            &second,
            1,
            5,
            manifest.generation,
            DeviceSyncNamespace::Contacts,
            b"alice".to_vec(),
            None,
        )
        .unwrap();
        let forward = resolve_device_sync_events(&manifest, [older.clone(), newer.clone()]);
        let reverse = resolve_device_sync_events(&manifest, [newer.clone(), older]);
        assert_eq!(forward, reverse);
        assert_eq!(
            forward
                .get(&(DeviceSyncNamespace::Contacts, b"alice".to_vec()))
                .unwrap(),
            &newer
        );
    }

    #[test]
    fn encrypted_bundle_binds_direction_sequence_and_revocation_cutoff() {
        let (account, first, second, mut manifest, mut rng) = fixture();
        let accepted = DeviceSyncEvent::sign(
            account.public().ed,
            &first,
            1,
            1,
            manifest.generation,
            DeviceSyncNamespace::Verification,
            b"peer".to_vec(),
            Some(vec![1]),
        )
        .unwrap();
        let root = [9u8; 32];
        let bundle = DeviceSyncBundle::seal(
            &root,
            first.public().ed,
            second.public().ed,
            1,
            manifest.clone(),
            vec![accepted],
            &mut rng,
        )
        .unwrap();
        let opened = bundle
            .open(&root, &second.public().ed, &first.public().ed)
            .unwrap();
        assert_eq!(opened.events.len(), 1);
        assert!(bundle
            .open(&root, &first.public().ed, &second.public().ed)
            .is_err());

        manifest
            .revoke_device(&account, &first.public().ed, 20, 1)
            .unwrap();
        let rejected = DeviceSyncEvent::sign(
            account.public().ed,
            &first,
            2,
            2,
            manifest.generation,
            DeviceSyncNamespace::Verification,
            b"peer".to_vec(),
            Some(vec![0]),
        )
        .unwrap();
        assert!(rejected.verify(&manifest).is_err());
    }
}
