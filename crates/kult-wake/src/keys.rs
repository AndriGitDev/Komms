use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::CryptoRngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{Result, WakeError};

const KEY_FILE_MAGIC: &[u8; 4] = b"KWK1";
const KEY_FILE_VERSION: u8 = 1;
const KEY_FILE_LEN: usize = 4 + 1 + 3 + 4 + 8 + 32;
const SEALED_OVERHEAD: usize = 16;

/// Non-secret metadata for one gateway capability-encryption key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WakeKeyMetadata {
    /// Operator-assigned non-zero key id carried by capabilities.
    pub key_id: u32,
    /// Coarse Unix activation time recorded in the key file.
    pub activated_at: u64,
    /// SHA-256 fingerprint of the version, id, activation time, and key bytes.
    pub fingerprint: [u8; 32],
}

/// HSM/KMS-compatible capability-encryption boundary.
///
/// Implementations perform authenticated encryption without exporting raw key
/// material to [`crate::WakeGateway`].
pub trait CapabilityKeyProvider: Send + Sync {
    /// Current non-zero key id used for newly issued capabilities.
    fn active_key_id(&self) -> u32;

    /// Seal one payload under the active key.
    fn seal_active(&self, nonce: &[u8; 24], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>>;

    /// Open one payload by the versioned key id carried in the capability.
    fn open(
        &self,
        key_id: u32,
        nonce: &[u8; 24],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>>;
}

/// Owner-only file-backed development/operator keyring.
///
/// Production deployments can implement [`CapabilityKeyProvider`] with
/// non-exportable HSM/KMS operations. Rotation keeps the prior key files
/// configured for at least the maximum capability lifetime.
pub struct FileCapabilityKeyring {
    active: u32,
    keys: BTreeMap<u32, Zeroizing<[u8; 32]>>,
    metadata: Vec<WakeKeyMetadata>,
}

impl FileCapabilityKeyring {
    /// Load a bounded set of distinct owner-only key files.
    pub fn open(active: u32, paths: &[PathBuf]) -> Result<Self> {
        if active == 0 || paths.is_empty() || paths.len() > 8 {
            return Err(WakeError::Invalid(
                "wake keyring must contain 1..=8 keys and a non-zero active id",
            ));
        }
        let mut keys = BTreeMap::new();
        let mut metadata = Vec::with_capacity(paths.len());
        for path in paths {
            let (entry, key) = read_key(path)?;
            if keys.insert(entry.key_id, key).is_some() {
                return Err(WakeError::Invalid("duplicate wake key id"));
            }
            metadata.push(entry);
        }
        if !keys.contains_key(&active) {
            return Err(WakeError::Invalid("active wake key is not loaded"));
        }
        metadata.sort_by_key(|entry| entry.key_id);
        Ok(Self {
            active,
            keys,
            metadata,
        })
    }

    /// Non-secret loaded key metadata.
    pub fn metadata(&self) -> &[WakeKeyMetadata] {
        &self.metadata
    }
}

impl CapabilityKeyProvider for FileCapabilityKeyring {
    fn active_key_id(&self) -> u32 {
        self.active
    }

    fn seal_active(&self, nonce: &[u8; 24], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let key = self.keys.get(&self.active).ok_or(WakeError::Key)?;
        XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| WakeError::Key)?
            .encrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| WakeError::Key)
    }

    fn open(
        &self,
        key_id: u32,
        nonce: &[u8; 24],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if ciphertext.len() < SEALED_OVERHEAD {
            return Err(WakeError::Key);
        }
        let key = self.keys.get(&key_id).ok_or(WakeError::Key)?;
        XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| WakeError::Key)?
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| WakeError::Key)
    }
}

/// Generate one new owner-only capability key file without overwriting.
pub fn generate_capability_key(
    path: &Path,
    key_id: u32,
    activated_at: u64,
    rng: &mut impl CryptoRngCore,
) -> Result<WakeKeyMetadata> {
    if !path.is_absolute() || key_id == 0 || activated_at == 0 {
        return Err(WakeError::Invalid(
            "wake key path must be absolute and key metadata non-zero",
        ));
    }
    let mut key = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(key.as_mut());
    if key.iter().all(|byte| *byte == 0) {
        return Err(WakeError::Key);
    }
    let mut encoded = Zeroizing::new([0u8; KEY_FILE_LEN]);
    encoded[..4].copy_from_slice(KEY_FILE_MAGIC);
    encoded[4] = KEY_FILE_VERSION;
    encoded[8..12].copy_from_slice(&key_id.to_be_bytes());
    encoded[12..20].copy_from_slice(&activated_at.to_be_bytes());
    encoded[20..].copy_from_slice(key.as_ref());

    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    file.write_all(encoded.as_ref())?;
    file.sync_all()?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    let metadata = key_metadata(key_id, activated_at, &key);
    encoded.zeroize();
    Ok(metadata)
}

fn read_key(path: &Path) -> Result<(WakeKeyMetadata, Zeroizing<[u8; 32]>)> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() != KEY_FILE_LEN as u64
    {
        return Err(WakeError::Invalid(
            "wake key must be an exact regular non-symlink file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(WakeError::Invalid(
                "wake key must not be group- or world-accessible",
            ));
        }
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    let mut encoded = Zeroizing::new([0u8; KEY_FILE_LEN]);
    file.read_exact(encoded.as_mut())?;
    let mut trailing = [0u8; 1];
    if file.read(&mut trailing)? != 0
        || &encoded[..4] != KEY_FILE_MAGIC
        || encoded[4] != KEY_FILE_VERSION
        || encoded[5..8].iter().any(|byte| *byte != 0)
    {
        return Err(WakeError::Invalid("wake key encoding is invalid"));
    }
    let key_id = u32::from_be_bytes(
        encoded[8..12]
            .try_into()
            .map_err(|_| WakeError::Invalid("wake key id"))?,
    );
    let activated_at = u64::from_be_bytes(
        encoded[12..20]
            .try_into()
            .map_err(|_| WakeError::Invalid("wake key activation"))?,
    );
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&encoded[20..]);
    if key_id == 0 || activated_at == 0 || key.iter().all(|byte| *byte == 0) {
        return Err(WakeError::Invalid("wake key fields are invalid"));
    }
    Ok((key_metadata(key_id, activated_at, &key), key))
}

fn key_metadata(key_id: u32, activated_at: u64, key: &[u8; 32]) -> WakeKeyMetadata {
    let mut hasher = Sha256::new();
    hasher.update(KEY_FILE_MAGIC);
    hasher.update([KEY_FILE_VERSION]);
    hasher.update(key_id.to_be_bytes());
    hasher.update(activated_at.to_be_bytes());
    hasher.update(key);
    WakeKeyMetadata {
        key_id,
        activated_at,
        fingerprint: hasher.finalize().into(),
    }
}

#[cfg(test)]
mod tests {
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;

    #[test]
    fn owner_only_keyring_seals_opens_and_rotates() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("first.key");
        let second = directory.path().join("second.key");
        let mut rng = StdRng::seed_from_u64(19);
        generate_capability_key(&first, 1, 100, &mut rng).unwrap();
        generate_capability_key(&second, 2, 200, &mut rng).unwrap();
        let keyring = FileCapabilityKeyring::open(2, &[first.clone(), second.clone()]).unwrap();
        assert_eq!(keyring.active_key_id(), 2);
        assert_eq!(keyring.metadata().len(), 2);
        let nonce = [7u8; 24];
        let sealed = keyring.seal_active(&nonce, b"secret", b"aad").unwrap();
        assert_eq!(
            keyring.open(2, &nonce, &sealed, b"aad").unwrap().as_slice(),
            b"secret"
        );
        assert!(keyring.open(1, &nonce, &sealed, b"aad").is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&first, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(FileCapabilityKeyring::open(2, &[first, second]).is_err());
        }
    }
}
