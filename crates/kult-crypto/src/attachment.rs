//! Fixed-record attachment chunk cryptography (ADR-0015).

use alloc::vec;
use alloc::vec::Vec;
use zeroize::Zeroizing;

use crate::{util, CryptoError, Result};

/// Exact attachment data bytes in one non-final chunk.
pub const ATTACHMENT_CHUNK_DATA_LEN: usize = 49_152;
/// Exact plaintext size before XChaCha20-Poly1305 sealing.
pub const ATTACHMENT_CHUNK_PLAINTEXT_LEN: usize = 49_156;
/// Exact end-to-end sealed chunk size.
pub const ATTACHMENT_SEALED_CHUNK_LEN: usize = 49_172;

const OBJECT_INFO: &[u8] = b"KAT-object-v1";
const CHUNK_INFO: &[u8] = b"KAT-chunk-v1";
const CHUNK_AD: &[u8] = b"KAT-chunk-ad-v1";
const ZERO_NONCE: [u8; 24] = [0; 24];

/// Scope used when binding an attachment chunk to its conversation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AttachmentChunkScope {
    /// A pairwise conversation.
    Pairwise = 0,
    /// A sender-key group conversation.
    Group = 1,
}

/// All manifest-derived context authenticated by one attachment chunk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachmentChunkContext {
    /// Pairwise or group scope.
    pub scope: AttachmentChunkScope,
    /// Pairwise conversation hash or group id.
    pub scope_id: [u8; 32],
    /// Ed25519 identity key of the manifest author.
    pub manifest_author: [u8; 32],
    /// ADR-0014 content id of the Attachment manifest.
    pub manifest_content_id: [u8; 16],
    /// Random object id from the manifest.
    pub object_id: [u8; 16],
    /// Object role: zero for primary, one for preview.
    pub role: u8,
    /// Exact unpadded object length.
    pub total_len: u64,
    /// Exact chunk count derived from `total_len`.
    pub chunk_count: u32,
    /// BLAKE3 of the exact unpadded object bytes.
    pub content_hash: [u8; 32],
}

/// Derive the stable pairwise attachment scope id from two identity keys.
pub fn attachment_pairwise_scope_id(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (first, second) = if a <= b { (a, b) } else { (b, a) };
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"KAT-pairwise-scope-v1");
    hasher.update(first);
    hasher.update(second);
    *hasher.finalize().as_bytes()
}

/// Seal one manifest-bounded attachment data chunk.
///
/// The returned 49,172 bytes are deterministic for an attachment key,
/// context, index, and data tuple so retries and group fan-out reuse exact
/// ciphertext. Callers must never reuse that tuple with different data.
pub fn seal_attachment_chunk(
    attachment_key: &[u8; 32],
    context: &AttachmentChunkContext,
    index: u32,
    data: &[u8],
) -> Result<Vec<u8>> {
    let actual_len = validate_context_index(context, index)?;
    if data.len() != actual_len {
        return Err(CryptoError::InvalidMessage);
    }
    let (chunk_key, ad) = chunk_key_and_ad(attachment_key, context, index, actual_len as u32);
    let mut plaintext = Zeroizing::new(vec![0u8; ATTACHMENT_CHUNK_PLAINTEXT_LEN]);
    plaintext[..4].copy_from_slice(&(actual_len as u32).to_le_bytes());
    plaintext[4..4 + actual_len].copy_from_slice(data);
    Ok(util::aead_encrypt_with_nonce(
        &chunk_key,
        &ZERO_NONCE,
        &ad,
        &plaintext,
    ))
}

/// Authenticate and open one fixed attachment chunk.
///
/// Only the exact unpadded data bytes are returned. Header mismatch or
/// non-zero fixed padding fails closed even after successful AEAD open.
pub fn open_attachment_chunk(
    attachment_key: &[u8; 32],
    context: &AttachmentChunkContext,
    index: u32,
    sealed: &[u8],
) -> Result<Vec<u8>> {
    let actual_len = validate_context_index(context, index)?;
    if sealed.len() != ATTACHMENT_SEALED_CHUNK_LEN {
        return Err(CryptoError::InvalidMessage);
    }
    let (chunk_key, ad) = chunk_key_and_ad(attachment_key, context, index, actual_len as u32);
    let plaintext = Zeroizing::new(util::aead_decrypt_with_nonce(
        &chunk_key,
        &ZERO_NONCE,
        &ad,
        sealed,
    )?);
    if plaintext.len() != ATTACHMENT_CHUNK_PLAINTEXT_LEN
        || u32::from_le_bytes(plaintext[..4].try_into().expect("fixed slice")) as usize
            != actual_len
        || plaintext[4 + actual_len..].iter().any(|byte| *byte != 0)
    {
        return Err(CryptoError::InvalidMessage);
    }
    Ok(plaintext[4..4 + actual_len].to_vec())
}

fn validate_context_index(context: &AttachmentChunkContext, index: u32) -> Result<usize> {
    if context.role > 1 || context.chunk_count != chunk_count(context.total_len) {
        return Err(CryptoError::InvalidMessage);
    }
    let max_len = if context.role == 0 {
        536_870_912
    } else {
        262_144
    };
    if context.total_len > max_len || index >= context.chunk_count {
        return Err(CryptoError::InvalidMessage);
    }
    let consumed = u64::from(index) * ATTACHMENT_CHUNK_DATA_LEN as u64;
    Ok(core::cmp::min(
        context.total_len - consumed,
        ATTACHMENT_CHUNK_DATA_LEN as u64,
    ) as usize)
}

const fn chunk_count(total_len: u64) -> u32 {
    if total_len == 0 {
        0
    } else {
        ((total_len - 1) / ATTACHMENT_CHUNK_DATA_LEN as u64 + 1) as u32
    }
}

fn chunk_key_and_ad(
    attachment_key: &[u8; 32],
    context: &AttachmentChunkContext,
    index: u32,
    actual_len: u32,
) -> (Zeroizing<[u8; 32]>, Vec<u8>) {
    let object_key = derive_object_key(attachment_key, context);
    let chunk_key = util::hkdf32(Some(&index.to_le_bytes()), object_key.as_ref(), CHUNK_INFO);

    let mut ad = Vec::with_capacity(CHUNK_AD.len() + 150);
    ad.extend_from_slice(CHUNK_AD);
    ad.push(context.scope as u8);
    ad.extend_from_slice(&context.scope_id);
    ad.extend_from_slice(&context.manifest_author);
    ad.extend_from_slice(&context.manifest_content_id);
    ad.extend_from_slice(&context.object_id);
    ad.push(context.role);
    ad.extend_from_slice(&index.to_le_bytes());
    ad.extend_from_slice(&context.total_len.to_le_bytes());
    ad.extend_from_slice(&actual_len.to_le_bytes());
    ad.extend_from_slice(&context.chunk_count.to_le_bytes());
    ad.extend_from_slice(&context.content_hash);
    (chunk_key, ad)
}

fn derive_object_key(
    attachment_key: &[u8; 32],
    context: &AttachmentChunkContext,
) -> Zeroizing<[u8; 32]> {
    let mut object_info = Vec::with_capacity(OBJECT_INFO.len() + 82);
    object_info.extend_from_slice(OBJECT_INFO);
    object_info.push(context.scope as u8);
    object_info.extend_from_slice(&context.scope_id);
    object_info.extend_from_slice(&context.manifest_author);
    object_info.extend_from_slice(&context.manifest_content_id);
    object_info.push(context.role);
    util::hkdf32(Some(&context.object_id), attachment_key, &object_info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bulk_hash;

    fn context(total_len: u64) -> AttachmentChunkContext {
        AttachmentChunkContext {
            scope: AttachmentChunkScope::Pairwise,
            scope_id: [1; 32],
            manifest_author: [2; 32],
            manifest_content_id: [3; 16],
            object_id: [4; 16],
            role: 0,
            total_len,
            chunk_count: chunk_count(total_len),
            content_hash: [5; 32],
        }
    }

    #[test]
    fn full_and_final_chunks_round_trip_with_stable_ciphertext() {
        let key = [7; 32];
        let full = vec![8; ATTACHMENT_CHUNK_DATA_LEN];
        let full_context = context(ATTACHMENT_CHUNK_DATA_LEN as u64);
        let first = seal_attachment_chunk(&key, &full_context, 0, &full).unwrap();
        let retry = seal_attachment_chunk(&key, &full_context, 0, &full).unwrap();
        assert_eq!(first, retry);
        assert_eq!(first.len(), ATTACHMENT_SEALED_CHUNK_LEN);
        assert_eq!(
            open_attachment_chunk(&key, &full_context, 0, &first).unwrap(),
            full
        );

        let final_context = context(ATTACHMENT_CHUNK_DATA_LEN as u64 + 1);
        let final_chunk = seal_attachment_chunk(&key, &final_context, 1, &[9]).unwrap();
        assert_eq!(
            open_attachment_chunk(&key, &final_context, 1, &final_chunk).unwrap(),
            [9]
        );
    }

    #[test]
    fn golden_keys_ciphertext_hash_and_scope() {
        let key = [7; 32];
        let context = context(1);
        assert_eq!(
            hex::encode(*derive_object_key(&key, &context)),
            "dde7f39e4f67748872d5f21dc35fe7d3a8eff4bbece2e360bf83b9e78a9e08ea"
        );
        let (chunk_key, ad) = chunk_key_and_ad(&key, &context, 0, 1);
        assert_eq!(
            hex::encode(*chunk_key),
            "399f71e141d1474d78a2324fc9c92502f2dfe41ce5f3c1e6032266021d4dde86"
        );
        assert_eq!(
            bulk_hash(&ad),
            [
                232, 113, 36, 75, 53, 66, 231, 148, 110, 180, 66, 12, 59, 175, 140, 94, 223, 104,
                17, 45, 188, 184, 87, 18, 45, 116, 25, 45, 22, 111, 117, 98,
            ]
        );
        let sealed = seal_attachment_chunk(&key, &context, 0, &[8]).unwrap();
        assert_eq!(
            bulk_hash(&sealed),
            [
                24, 139, 82, 186, 226, 37, 206, 151, 177, 193, 14, 251, 57, 57, 21, 50, 185, 43,
                126, 48, 14, 205, 44, 206, 86, 204, 181, 135, 123, 156, 85, 146,
            ]
        );
        assert_eq!(
            attachment_pairwise_scope_id(&[9; 32], &[6; 32]),
            [
                106, 68, 141, 171, 193, 180, 200, 198, 51, 246, 127, 43, 249, 30, 231, 250, 166,
                217, 229, 199, 170, 67, 213, 182, 39, 204, 28, 114, 27, 135, 35, 247,
            ]
        );
    }

    #[test]
    fn wrong_context_tamper_and_noncanonical_inputs_fail() {
        let key = [7; 32];
        let chunk_context = context(1);
        let sealed = seal_attachment_chunk(&key, &chunk_context, 0, &[8]).unwrap();
        let mut wrong = chunk_context;
        wrong.scope_id[0] ^= 1;
        assert_eq!(
            open_attachment_chunk(&key, &wrong, 0, &sealed),
            Err(CryptoError::MessageAuthentication)
        );

        let mut tampered = sealed;
        tampered[10] ^= 1;
        assert_eq!(
            open_attachment_chunk(&key, &chunk_context, 0, &tampered),
            Err(CryptoError::MessageAuthentication)
        );
        assert_eq!(
            seal_attachment_chunk(&key, &chunk_context, 0, &[]),
            Err(CryptoError::InvalidMessage)
        );
        assert_eq!(
            seal_attachment_chunk(&key, &context(0), 0, &[]),
            Err(CryptoError::InvalidMessage)
        );
    }

    #[test]
    fn logical_boundaries_validate_without_whole_object_allocation() {
        for len in [1, 49_151, 49_152, 49_153, 262_144, 536_870_912] {
            let context = context(len);
            let last = context.chunk_count - 1;
            let expected = ((len - 1) % ATTACHMENT_CHUNK_DATA_LEN as u64 + 1) as usize;
            assert_eq!(validate_context_index(&context, last).unwrap(), expected);
        }
    }
}
