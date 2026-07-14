//! Canonical encrypted attachment manifests (ADR-0015).

use alloc::vec::Vec;

use crate::{ProtocolError, Result};

/// Attachment manifest format version implemented by this crate.
pub const ATTACHMENT_MANIFEST_VERSION: u8 = 1;
/// Maximum canonical attachment-manifest payload size.
pub const MAX_ATTACHMENT_MANIFEST_LEN: usize = 1_024;
/// Exact data bytes carried by every non-final attachment chunk.
pub const ATTACHMENT_CHUNK_DATA_LEN: u32 = 49_152;
/// Maximum primary-object size (512 MiB).
pub const MAX_PRIMARY_OBJECT_LEN: u64 = 536_870_912;
/// Maximum primary-object chunk count.
pub const MAX_PRIMARY_CHUNKS: u32 = 10_923;
/// Maximum preview-object size (256 KiB).
pub const MAX_PREVIEW_OBJECT_LEN: u64 = 262_144;
/// Maximum preview-object chunk count.
pub const MAX_PREVIEW_CHUNKS: u32 = 6;
/// Maximum UTF-8 filename size in bytes.
pub const MAX_ATTACHMENT_FILENAME_LEN: usize = 255;
/// Maximum ASCII media-type size in bytes.
pub const MAX_ATTACHMENT_MEDIA_TYPE_LEN: usize = 127;

/// Role of an object inside an attachment manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AttachmentRole {
    /// The offered file or media object.
    Primary = 0,
    /// A sandboxed image preview of the primary object.
    Preview = 1,
}

impl AttachmentRole {
    pub(crate) fn decode(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Primary),
            1 => Ok(Self::Preview),
            _ => Err(ProtocolError::Malformed),
        }
    }
}

/// One borrowed object descriptor from a canonical attachment manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachmentObject<'a> {
    /// Primary or preview role.
    pub role: AttachmentRole,
    /// Random object identifier, unique within the manifest.
    pub object_id: [u8; 16],
    /// Exact unpadded object length.
    pub total_len: u64,
    /// Fixed v1 chunk data length; always 49,152.
    pub chunk_data_len: u32,
    /// Exact ceiling of `total_len / chunk_data_len`.
    pub chunk_count: u32,
    /// BLAKE3 of the exact unpadded object bytes.
    pub content_hash: [u8; 32],
    /// Authenticated lowercase media-type hint.
    pub media_type: &'a str,
    /// Optional sanitized sender filename.
    pub filename: Option<&'a str>,
}

/// A canonical v1 attachment manifest borrowing its string fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachmentManifest<'a> {
    /// Random key from which per-object and per-chunk keys are derived.
    pub attachment_key: [u8; 32],
    /// Mandatory primary object.
    pub primary: AttachmentObject<'a>,
    /// Optional image preview of the primary object.
    pub preview: Option<AttachmentObject<'a>>,
}

/// Classification of an authenticated attachment-manifest payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)] // borrowed, allocation-free decoder outcome by design
pub enum DecodedAttachmentManifest<'a> {
    /// A supported, canonical v1 manifest.
    Manifest(AttachmentManifest<'a>),
    /// A structurally bounded manifest version or flag set not understood.
    Unsupported,
    /// Bytes that violate canonical v1 framing or bounds.
    Malformed,
}

/// Encode a canonical attachment-manifest payload.
pub fn encode_attachment_manifest(manifest: &AttachmentManifest<'_>) -> Result<Vec<u8>> {
    validate_manifest(manifest)?;
    let objects = usize::from(manifest.preview.is_some()) + 1;
    let mut out = Vec::with_capacity(256);
    out.push(ATTACHMENT_MANIFEST_VERSION);
    out.push(0);
    out.extend_from_slice(&manifest.attachment_key);
    out.push(objects as u8);
    encode_object(&mut out, &manifest.primary)?;
    if let Some(preview) = manifest.preview {
        encode_object(&mut out, &preview)?;
    }
    if out.len() > MAX_ATTACHMENT_MANIFEST_LEN {
        return Err(ProtocolError::TooLarge);
    }
    Ok(out)
}

/// Decode and classify a complete authenticated attachment-manifest payload.
pub fn decode_attachment_manifest(bytes: &[u8]) -> DecodedAttachmentManifest<'_> {
    if bytes.len() > MAX_ATTACHMENT_MANIFEST_LEN || bytes.len() < 2 {
        return DecodedAttachmentManifest::Malformed;
    }
    if bytes[0] != ATTACHMENT_MANIFEST_VERSION || bytes[1] != 0 {
        return DecodedAttachmentManifest::Unsupported;
    }
    if bytes.len() < 35 {
        return DecodedAttachmentManifest::Malformed;
    }

    match decode_v1(bytes) {
        Ok(manifest) => DecodedAttachmentManifest::Manifest(manifest),
        Err(_) => DecodedAttachmentManifest::Malformed,
    }
}

fn decode_v1(bytes: &[u8]) -> Result<AttachmentManifest<'_>> {
    let mut offset = 2;
    let attachment_key = take_array::<32>(bytes, &mut offset)?;
    let object_count = take_u8(bytes, &mut offset)?;
    if !(1..=2).contains(&object_count) {
        return Err(ProtocolError::Malformed);
    }
    let primary = decode_object(bytes, &mut offset)?;
    let preview = if object_count == 2 {
        Some(decode_object(bytes, &mut offset)?)
    } else {
        None
    };
    if offset != bytes.len() {
        return Err(ProtocolError::Malformed);
    }
    let manifest = AttachmentManifest {
        attachment_key,
        primary,
        preview,
    };
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn encode_object(out: &mut Vec<u8>, object: &AttachmentObject<'_>) -> Result<()> {
    validate_object(object)?;
    out.push(object.role as u8);
    out.extend_from_slice(&object.object_id);
    out.extend_from_slice(&object.total_len.to_le_bytes());
    out.extend_from_slice(&object.chunk_data_len.to_le_bytes());
    out.extend_from_slice(&object.chunk_count.to_le_bytes());
    out.extend_from_slice(&object.content_hash);
    out.push(object.media_type.len() as u8);
    out.extend_from_slice(object.media_type.as_bytes());
    let filename = object.filename.unwrap_or("").as_bytes();
    out.extend_from_slice(&(filename.len() as u16).to_le_bytes());
    out.extend_from_slice(filename);
    Ok(())
}

fn decode_object<'a>(bytes: &'a [u8], offset: &mut usize) -> Result<AttachmentObject<'a>> {
    let role = AttachmentRole::decode(take_u8(bytes, offset)?)?;
    let object_id = take_array::<16>(bytes, offset)?;
    let total_len = take_u64(bytes, offset)?;
    let chunk_data_len = take_u32(bytes, offset)?;
    let chunk_count = take_u32(bytes, offset)?;
    let content_hash = take_array::<32>(bytes, offset)?;
    let media_len = take_u8(bytes, offset)? as usize;
    let media_bytes = take(bytes, offset, media_len)?;
    let media_type = core::str::from_utf8(media_bytes).map_err(|_| ProtocolError::Malformed)?;
    let filename_len = take_u16(bytes, offset)? as usize;
    let filename_bytes = take(bytes, offset, filename_len)?;
    let filename = if filename_bytes.is_empty() {
        None
    } else {
        Some(core::str::from_utf8(filename_bytes).map_err(|_| ProtocolError::Malformed)?)
    };
    Ok(AttachmentObject {
        role,
        object_id,
        total_len,
        chunk_data_len,
        chunk_count,
        content_hash,
        media_type,
        filename,
    })
}

fn validate_manifest(manifest: &AttachmentManifest<'_>) -> Result<()> {
    if manifest.primary.role != AttachmentRole::Primary {
        return Err(ProtocolError::Malformed);
    }
    validate_object(&manifest.primary)?;
    if let Some(preview) = manifest.preview {
        if preview.role != AttachmentRole::Preview
            || preview.object_id == manifest.primary.object_id
            || preview.filename.is_some()
        {
            return Err(ProtocolError::Malformed);
        }
        validate_object(&preview)?;
    }
    Ok(())
}

fn validate_object(object: &AttachmentObject<'_>) -> Result<()> {
    if object.chunk_data_len != ATTACHMENT_CHUNK_DATA_LEN
        || object.chunk_count != chunk_count(object.total_len)
        || (object.total_len == 0 && object.content_hash != *blake3::hash(&[]).as_bytes())
        || !valid_media_type(object.media_type)
        || !valid_filename(object.filename)
    {
        return Err(ProtocolError::Malformed);
    }
    match object.role {
        AttachmentRole::Primary => {
            if object.total_len > MAX_PRIMARY_OBJECT_LEN || object.chunk_count > MAX_PRIMARY_CHUNKS
            {
                return Err(ProtocolError::TooLarge);
            }
        }
        AttachmentRole::Preview => {
            if object.total_len > MAX_PREVIEW_OBJECT_LEN
                || object.chunk_count > MAX_PREVIEW_CHUNKS
                || !matches!(object.media_type, "image/jpeg" | "image/png")
                || object.filename.is_some()
            {
                return Err(ProtocolError::Malformed);
            }
        }
    }
    Ok(())
}

/// Return the exact v1 chunk count for a logical object length.
pub const fn attachment_chunk_count(total_len: u64) -> u32 {
    chunk_count(total_len)
}

const fn chunk_count(total_len: u64) -> u32 {
    if total_len == 0 {
        0
    } else {
        ((total_len - 1) / ATTACHMENT_CHUNK_DATA_LEN as u64 + 1) as u32
    }
}

fn valid_media_type(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_ATTACHMENT_MEDIA_TYPE_LEN || !bytes.is_ascii() {
        return false;
    }
    let mut slash = None;
    for (index, &byte) in bytes.iter().enumerate() {
        if byte == b'/' {
            if slash.replace(index).is_some() {
                return false;
            }
        } else if !matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'!' | b'#' | b'$' | b'&' | b'^' | b'_' | b'.' | b'+' | b'-')
        {
            return false;
        }
    }
    matches!(slash, Some(index) if index > 0 && index + 1 < bytes.len())
}

fn valid_filename(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return true;
    };
    if value.is_empty()
        || value.len() > MAX_ATTACHMENT_FILENAME_LEN
        || matches!(value, "." | "..")
        || value.contains(['/', '\\'])
    {
        return false;
    }
    !value
        .chars()
        .any(|c| matches!(c as u32, 0x00..=0x1f | 0x7f..=0x9f))
}

fn take<'a>(bytes: &'a [u8], offset: &mut usize, len: usize) -> Result<&'a [u8]> {
    let end = offset.checked_add(len).ok_or(ProtocolError::Malformed)?;
    let value = bytes.get(*offset..end).ok_or(ProtocolError::Malformed)?;
    *offset = end;
    Ok(value)
}

fn take_array<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N]> {
    take(bytes, offset, N)?
        .try_into()
        .map_err(|_| ProtocolError::Malformed)
}

fn take_u8(bytes: &[u8], offset: &mut usize) -> Result<u8> {
    Ok(take(bytes, offset, 1)?[0])
}

fn take_u16(bytes: &[u8], offset: &mut usize) -> Result<u16> {
    Ok(u16::from_le_bytes(take_array(bytes, offset)?))
}

fn take_u32(bytes: &[u8], offset: &mut usize) -> Result<u32> {
    Ok(u32::from_le_bytes(take_array(bytes, offset)?))
}

fn take_u64(bytes: &[u8], offset: &mut usize) -> Result<u64> {
    Ok(u64::from_le_bytes(take_array(bytes, offset)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn manifest<'a>(
        media_type: &'a str,
        filename: Option<&'a str>,
        len: u64,
    ) -> AttachmentManifest<'a> {
        AttachmentManifest {
            attachment_key: [0x11; 32],
            primary: AttachmentObject {
                role: AttachmentRole::Primary,
                object_id: [0x22; 16],
                total_len: len,
                chunk_data_len: ATTACHMENT_CHUNK_DATA_LEN,
                chunk_count: attachment_chunk_count(len),
                content_hash: if len == 0 {
                    *blake3::hash(&[]).as_bytes()
                } else {
                    [0x33; 32]
                },
                media_type,
                filename,
            },
            preview: None,
        }
    }

    #[test]
    fn manifest_golden_vector_and_round_trip() {
        let manifest = manifest("text/plain", Some("a.txt"), 1);
        let bytes = encode_attachment_manifest(&manifest).unwrap();
        let mut expected = vec![1, 0];
        expected.extend_from_slice(&[0x11; 32]);
        expected.push(1);
        expected.push(0);
        expected.extend_from_slice(&[0x22; 16]);
        expected.extend_from_slice(&1u64.to_le_bytes());
        expected.extend_from_slice(&49_152u32.to_le_bytes());
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(&[0x33; 32]);
        expected.push(10);
        expected.extend_from_slice(b"text/plain");
        expected.extend_from_slice(&5u16.to_le_bytes());
        expected.extend_from_slice(b"a.txt");
        assert_eq!(bytes, expected);
        assert_eq!(
            decode_attachment_manifest(&bytes),
            DecodedAttachmentManifest::Manifest(manifest)
        );
    }

    #[test]
    fn logical_boundaries_do_not_allocate_objects() {
        for (len, count) in [
            (0, 0),
            (1, 1),
            (49_151, 1),
            (49_152, 1),
            (49_153, 2),
            (262_144, 6),
            (MAX_PRIMARY_OBJECT_LEN, 10_923),
        ] {
            let manifest = manifest("application/octet-stream", None, len);
            assert_eq!(manifest.primary.chunk_count, count);
            let bytes = encode_attachment_manifest(&manifest).unwrap();
            assert!(matches!(
                decode_attachment_manifest(&bytes),
                DecodedAttachmentManifest::Manifest(_)
            ));
        }
    }

    #[test]
    fn preview_and_string_rules_are_strict() {
        for media in [
            "Text/plain",
            "text",
            "text/",
            "/plain",
            "text/plain; charset=x",
            "text//plain",
        ] {
            assert!(
                encode_attachment_manifest(&manifest(media, None, 1)).is_err(),
                "{media}"
            );
        }
        for filename in ["", ".", "..", "a/b", "a\\b", "a\0b", "a\u{85}b"] {
            assert!(
                encode_attachment_manifest(&manifest("text/plain", Some(filename), 1)).is_err(),
                "{filename:?}"
            );
        }

        let mut with_preview = manifest("video/mp4", Some("clip.mp4"), 49_153);
        with_preview.preview = Some(AttachmentObject {
            role: AttachmentRole::Preview,
            object_id: [0x44; 16],
            total_len: 262_144,
            chunk_data_len: ATTACHMENT_CHUNK_DATA_LEN,
            chunk_count: 6,
            content_hash: [0x55; 32],
            media_type: "image/jpeg",
            filename: None,
        });
        let bytes = encode_attachment_manifest(&with_preview).unwrap();
        assert_eq!(
            decode_attachment_manifest(&bytes),
            DecodedAttachmentManifest::Manifest(with_preview)
        );
    }

    #[test]
    fn unknown_version_and_flags_are_unsupported() {
        let mut bytes = encode_attachment_manifest(&manifest("text/plain", None, 1)).unwrap();
        bytes[0] = 2;
        assert_eq!(
            decode_attachment_manifest(&bytes),
            DecodedAttachmentManifest::Unsupported
        );
        bytes[0] = 1;
        bytes[1] = 1;
        assert_eq!(
            decode_attachment_manifest(&bytes),
            DecodedAttachmentManifest::Unsupported
        );
    }

    proptest! {
        #[test]
        fn arbitrary_input_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = decode_attachment_manifest(&bytes);
        }
    }
}
