//! Receipt-compatible attachment bulk records (ADR-0015).

use alloc::vec::Vec;

use crate::{AttachmentRole, ProtocolError, Result};

/// Receipt-compatible prefix for encrypted attachment bulk records.
pub const ATTACHMENT_BULK_MAGIC: [u8; 6] = [0x00, 0x00, 0xff, b'K', b'A', b'B'];
/// Bulk record version implemented by this crate.
pub const ATTACHMENT_BULK_VERSION: u8 = 1;
/// Exact common-header size, including the payload length.
pub const ATTACHMENT_BULK_HEADER_LEN: usize = 110;
/// Maximum complete unpadded bulk record size.
pub const MAX_ATTACHMENT_BULK_LEN: usize = 65_535;
/// Maximum missing ranges in one request.
pub const MAX_MISSING_RANGES: usize = 64;
/// Fixed unpadded attachment-chunk plaintext size.
pub const ATTACHMENT_CHUNK_PLAINTEXT_LEN: usize = 49_156;
/// Fixed end-to-end sealed attachment-chunk size.
pub const ATTACHMENT_SEALED_CHUNK_LEN: usize = 49_172;

/// Conversation scope binding carried inside the encrypted bulk record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AttachmentScope {
    /// A two-party conversation.
    Pairwise = 0,
    /// A sender-key group conversation, served over pairwise sessions.
    Group = 1,
}

impl AttachmentScope {
    fn decode(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Pairwise),
            1 => Some(Self::Group),
            _ => None,
        }
    }
}

/// One canonical half-open missing range represented as start plus count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MissingRange {
    /// First missing chunk index.
    pub start: u32,
    /// Number of consecutive missing chunks.
    pub count: u32,
}

/// Fixed reason codes permitted on cancel and reject records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AttachmentReason {
    /// Explicit local user action.
    User = 0,
    /// Feature or media profile is unsupported.
    Unsupported = 1,
    /// Configured media quota would be exceeded.
    Quota = 2,
    /// Filesystem reserve would be violated.
    LowStorage = 3,
    /// Local carrier or download policy refused the transfer.
    Policy = 4,
    /// Authentication or final object integrity failed.
    Corrupt = 5,
}

impl AttachmentReason {
    fn decode(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::User),
            1 => Ok(Self::Unsupported),
            2 => Ok(Self::Quota),
            3 => Ok(Self::LowStorage),
            4 => Ok(Self::Policy),
            5 => Ok(Self::Corrupt),
            _ => Err(ProtocolError::Malformed),
        }
    }
}

/// Canonical v1 attachment bulk operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttachmentBulkOperation<'a> {
    /// Request or resume canonical missing chunk ranges.
    RequestMissing {
        /// Object role selected by the request.
        role: AttachmentRole,
        /// Strictly sorted, disjoint, non-adjacent missing ranges.
        ranges: Vec<MissingRange>,
    },
    /// One fixed-size independently sealed chunk.
    Chunk {
        /// Object role selected by the record.
        role: AttachmentRole,
        /// Zero-based chunk index.
        index: u32,
        /// Exact 49,172-byte end-to-end ciphertext.
        sealed_chunk: &'a [u8],
    },
    /// Receiver confirmation after durable complete-object verification.
    Complete {
        /// Completed object role.
        role: AttachmentRole,
        /// Manifest content hash reasserted by the receiver.
        content_hash: [u8; 32],
    },
    /// Stop transfer activity and release unreferenced partial data.
    Cancel(AttachmentReason),
    /// Durable receiver refusal until local user policy changes.
    Reject(AttachmentReason),
}

impl AttachmentBulkOperation<'_> {
    fn code(&self) -> u8 {
        match self {
            Self::RequestMissing { .. } => 0x01,
            Self::Chunk { .. } => 0x02,
            Self::Complete { .. } => 0x03,
            Self::Cancel(_) => 0x04,
            Self::Reject(_) => 0x05,
        }
    }
}

/// One canonical attachment bulk record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentBulkRecord<'a> {
    /// Pairwise or group conversation scope.
    pub scope: AttachmentScope,
    /// Pairwise conversation hash or group id.
    pub scope_id: [u8; 32],
    /// Ed25519 identity key of the manifest author.
    pub manifest_author: [u8; 32],
    /// ADR-0014 content id of the Attachment frame.
    pub manifest_content_id: [u8; 16],
    /// Random object id selected by the manifest.
    pub object_id: [u8; 16],
    /// Transfer operation and canonical payload.
    pub operation: AttachmentBulkOperation<'a>,
}

/// Classification of authenticated receipt-lane bytes with KAB magic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodedAttachmentBulkRecord<'a> {
    /// A supported canonical v1 record.
    Record(AttachmentBulkRecord<'a>),
    /// A bounded complete record using an unknown version, flag, scope, or operation.
    Unsupported,
    /// A KAB-prefixed body that violates common framing or a known payload contract.
    Malformed,
}

/// Return whether decrypted receipt-lane bytes begin with KAB bulk magic.
pub fn is_attachment_bulk_record(bytes: &[u8]) -> bool {
    bytes.starts_with(&ATTACHMENT_BULK_MAGIC)
}

/// Encode one canonical attachment bulk record.
pub fn encode_attachment_bulk_record(record: &AttachmentBulkRecord<'_>) -> Result<Vec<u8>> {
    let payload = encode_operation(&record.operation)?;
    let len = ATTACHMENT_BULK_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(ProtocolError::TooLarge)?;
    if len > MAX_ATTACHMENT_BULK_LEN {
        return Err(ProtocolError::TooLarge);
    }
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&ATTACHMENT_BULK_MAGIC);
    out.push(ATTACHMENT_BULK_VERSION);
    out.push(record.operation.code());
    out.push(0);
    out.push(record.scope as u8);
    out.extend_from_slice(&record.scope_id);
    out.extend_from_slice(&record.manifest_author);
    out.extend_from_slice(&record.manifest_content_id);
    out.extend_from_slice(&record.object_id);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Decode and classify a complete authenticated attachment bulk record.
pub fn decode_attachment_bulk_record(bytes: &[u8]) -> DecodedAttachmentBulkRecord<'_> {
    if !is_attachment_bulk_record(bytes)
        || bytes.len() < ATTACHMENT_BULK_HEADER_LEN
        || bytes.len() > MAX_ATTACHMENT_BULK_LEN
    {
        return DecodedAttachmentBulkRecord::Malformed;
    }
    let payload_len = u32::from_le_bytes(bytes[106..110].try_into().expect("fixed slice")) as usize;
    if payload_len != bytes.len() - ATTACHMENT_BULK_HEADER_LEN {
        return DecodedAttachmentBulkRecord::Malformed;
    }
    let Some(scope) = AttachmentScope::decode(bytes[9]) else {
        return DecodedAttachmentBulkRecord::Unsupported;
    };
    if bytes[6] != ATTACHMENT_BULK_VERSION || bytes[8] != 0 || !(1..=5).contains(&bytes[7]) {
        return DecodedAttachmentBulkRecord::Unsupported;
    }

    let payload = &bytes[ATTACHMENT_BULK_HEADER_LEN..];
    let operation = match decode_operation(bytes[7], payload) {
        Ok(operation) => operation,
        Err(_) => return DecodedAttachmentBulkRecord::Malformed,
    };
    DecodedAttachmentBulkRecord::Record(AttachmentBulkRecord {
        scope,
        scope_id: bytes[10..42].try_into().expect("fixed slice"),
        manifest_author: bytes[42..74].try_into().expect("fixed slice"),
        manifest_content_id: bytes[74..90].try_into().expect("fixed slice"),
        object_id: bytes[90..106].try_into().expect("fixed slice"),
        operation,
    })
}

/// Validate missing ranges against the resolved manifest object's chunk count.
pub fn validate_missing_ranges(ranges: &[MissingRange], chunk_count: u32) -> Result<()> {
    if ranges.len() > MAX_MISSING_RANGES {
        return Err(ProtocolError::TooLarge);
    }
    let mut previous_end = None;
    for range in ranges {
        if range.count == 0 {
            return Err(ProtocolError::Malformed);
        }
        let end = range
            .start
            .checked_add(range.count)
            .ok_or(ProtocolError::Malformed)?;
        if end > chunk_count || previous_end.is_some_and(|previous| previous >= range.start) {
            return Err(ProtocolError::Malformed);
        }
        previous_end = Some(end);
    }
    Ok(())
}

fn encode_operation(operation: &AttachmentBulkOperation<'_>) -> Result<Vec<u8>> {
    let mut payload = Vec::new();
    match operation {
        AttachmentBulkOperation::RequestMissing { role, ranges } => {
            validate_missing_ranges(ranges, u32::MAX)?;
            payload.push(*role as u8);
            payload.push(ranges.len() as u8);
            for range in ranges {
                payload.extend_from_slice(&range.start.to_le_bytes());
                payload.extend_from_slice(&range.count.to_le_bytes());
            }
        }
        AttachmentBulkOperation::Chunk {
            role,
            index,
            sealed_chunk,
        } => {
            if sealed_chunk.len() != ATTACHMENT_SEALED_CHUNK_LEN {
                return Err(ProtocolError::Malformed);
            }
            payload.push(*role as u8);
            payload.extend_from_slice(&index.to_le_bytes());
            payload.extend_from_slice(&(ATTACHMENT_SEALED_CHUNK_LEN as u32).to_le_bytes());
            payload.extend_from_slice(sealed_chunk);
        }
        AttachmentBulkOperation::Complete { role, content_hash } => {
            payload.push(*role as u8);
            payload.extend_from_slice(content_hash);
        }
        AttachmentBulkOperation::Cancel(reason) | AttachmentBulkOperation::Reject(reason) => {
            payload.push(*reason as u8);
        }
    }
    Ok(payload)
}

fn decode_operation(code: u8, payload: &[u8]) -> Result<AttachmentBulkOperation<'_>> {
    match code {
        0x01 => {
            if payload.len() < 2 {
                return Err(ProtocolError::Malformed);
            }
            let role = AttachmentRole::decode(payload[0])?;
            let count = payload[1] as usize;
            if count > MAX_MISSING_RANGES || payload.len() != 2 + count * 8 {
                return Err(ProtocolError::Malformed);
            }
            let mut ranges = Vec::with_capacity(count);
            for encoded in payload[2..].chunks_exact(8) {
                ranges.push(MissingRange {
                    start: u32::from_le_bytes(encoded[..4].try_into().expect("fixed slice")),
                    count: u32::from_le_bytes(encoded[4..].try_into().expect("fixed slice")),
                });
            }
            validate_missing_ranges(&ranges, u32::MAX)?;
            Ok(AttachmentBulkOperation::RequestMissing { role, ranges })
        }
        0x02 => {
            if payload.len() != 9 + ATTACHMENT_SEALED_CHUNK_LEN {
                return Err(ProtocolError::Malformed);
            }
            let role = AttachmentRole::decode(payload[0])?;
            let index = u32::from_le_bytes(payload[1..5].try_into().expect("fixed slice"));
            let sealed_len =
                u32::from_le_bytes(payload[5..9].try_into().expect("fixed slice")) as usize;
            if sealed_len != ATTACHMENT_SEALED_CHUNK_LEN {
                return Err(ProtocolError::Malformed);
            }
            Ok(AttachmentBulkOperation::Chunk {
                role,
                index,
                sealed_chunk: &payload[9..],
            })
        }
        0x03 => {
            if payload.len() != 33 {
                return Err(ProtocolError::Malformed);
            }
            Ok(AttachmentBulkOperation::Complete {
                role: AttachmentRole::decode(payload[0])?,
                content_hash: payload[1..].try_into().expect("fixed slice"),
            })
        }
        0x04 | 0x05 => {
            if payload.len() != 1 {
                return Err(ProtocolError::Malformed);
            }
            let reason = AttachmentReason::decode(payload[0])?;
            Ok(if code == 0x04 {
                AttachmentBulkOperation::Cancel(reason)
            } else {
                AttachmentBulkOperation::Reject(reason)
            })
        }
        _ => Err(ProtocolError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ReceiptPayload;
    use proptest::prelude::*;

    fn record<'a>(operation: AttachmentBulkOperation<'a>) -> AttachmentBulkRecord<'a> {
        AttachmentBulkRecord {
            scope: AttachmentScope::Pairwise,
            scope_id: [1; 32],
            manifest_author: [2; 32],
            manifest_content_id: [3; 16],
            object_id: [4; 16],
            operation,
        }
    }

    #[test]
    fn common_header_golden_and_old_receipt_compatibility() {
        let record = record(AttachmentBulkOperation::Cancel(AttachmentReason::User));
        let encoded = encode_attachment_bulk_record(&record).unwrap();
        assert_eq!(&encoded[..10], &[0, 0, 0xff, b'K', b'A', b'B', 1, 4, 0, 0]);
        assert_eq!(&encoded[106..110], &1u32.to_le_bytes());
        assert_eq!(
            decode_attachment_bulk_record(&encoded),
            DecodedAttachmentBulkRecord::Record(record)
        );
        assert_eq!(
            ReceiptPayload::decode(&encoded).unwrap(),
            ReceiptPayload::default()
        );
    }

    #[test]
    fn every_operation_round_trips() {
        let sealed = [9u8; ATTACHMENT_SEALED_CHUNK_LEN];
        let operations = [
            AttachmentBulkOperation::RequestMissing {
                role: AttachmentRole::Primary,
                ranges: vec![
                    MissingRange { start: 1, count: 2 },
                    MissingRange { start: 5, count: 1 },
                ],
            },
            AttachmentBulkOperation::Chunk {
                role: AttachmentRole::Primary,
                index: 7,
                sealed_chunk: &sealed,
            },
            AttachmentBulkOperation::Complete {
                role: AttachmentRole::Preview,
                content_hash: [8; 32],
            },
            AttachmentBulkOperation::Cancel(AttachmentReason::LowStorage),
            AttachmentBulkOperation::Reject(AttachmentReason::Policy),
        ];
        for operation in operations {
            let record = record(operation);
            let encoded = encode_attachment_bulk_record(&record).unwrap();
            assert_eq!(
                decode_attachment_bulk_record(&encoded),
                DecodedAttachmentBulkRecord::Record(record)
            );
        }

        let request =
            encode_attachment_bulk_record(&record(AttachmentBulkOperation::RequestMissing {
                role: AttachmentRole::Primary,
                ranges: vec![
                    MissingRange { start: 1, count: 2 },
                    MissingRange { start: 5, count: 1 },
                ],
            }))
            .unwrap();
        assert_eq!(
            &request[ATTACHMENT_BULK_HEADER_LEN..],
            &[0, 2, 1, 0, 0, 0, 2, 0, 0, 0, 5, 0, 0, 0, 1, 0, 0, 0]
        );
        let chunk = encode_attachment_bulk_record(&record(AttachmentBulkOperation::Chunk {
            role: AttachmentRole::Primary,
            index: 7,
            sealed_chunk: &sealed,
        }))
        .unwrap();
        assert_eq!(
            &chunk[ATTACHMENT_BULK_HEADER_LEN..ATTACHMENT_BULK_HEADER_LEN + 9],
            &[0, 7, 0, 0, 0, 0x14, 0xc0, 0, 0]
        );
        assert!(chunk[ATTACHMENT_BULK_HEADER_LEN + 9..]
            .iter()
            .all(|byte| *byte == 9));
        let complete = encode_attachment_bulk_record(&record(AttachmentBulkOperation::Complete {
            role: AttachmentRole::Preview,
            content_hash: [8; 32],
        }))
        .unwrap();
        assert_eq!(complete[ATTACHMENT_BULK_HEADER_LEN], 1);
        assert_eq!(&complete[ATTACHMENT_BULK_HEADER_LEN + 1..], &[8; 32]);
        let cancel = encode_attachment_bulk_record(&record(AttachmentBulkOperation::Cancel(
            AttachmentReason::LowStorage,
        )))
        .unwrap();
        assert_eq!(&cancel[ATTACHMENT_BULK_HEADER_LEN..], &[3]);
        let reject = encode_attachment_bulk_record(&record(AttachmentBulkOperation::Reject(
            AttachmentReason::Policy,
        )))
        .unwrap();
        assert_eq!(&reject[ATTACHMENT_BULK_HEADER_LEN..], &[4]);
    }

    #[test]
    fn ranges_must_be_sorted_disjoint_merged_and_bounded() {
        assert!(validate_missing_ranges(
            &[
                MissingRange { start: 0, count: 2 },
                MissingRange { start: 2, count: 1 }
            ],
            3
        )
        .is_err());
        assert!(validate_missing_ranges(
            &[
                MissingRange { start: 2, count: 1 },
                MissingRange { start: 1, count: 1 }
            ],
            3
        )
        .is_err());
        assert!(validate_missing_ranges(&[MissingRange { start: 0, count: 0 }], 3).is_err());
        assert!(validate_missing_ranges(&[MissingRange { start: 3, count: 1 }], 3).is_err());
        assert!(validate_missing_ranges(
            &[
                MissingRange { start: 0, count: 2 },
                MissingRange { start: 3, count: 1 }
            ],
            4
        )
        .is_ok());
    }

    #[test]
    fn malformed_lengths_and_unknown_fields_fail_closed() {
        let mut encoded = encode_attachment_bulk_record(&record(AttachmentBulkOperation::Cancel(
            AttachmentReason::User,
        )))
        .unwrap();
        encoded[106..110].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            decode_attachment_bulk_record(&encoded),
            DecodedAttachmentBulkRecord::Malformed
        );
        encoded[106..110].copy_from_slice(&1u32.to_le_bytes());
        encoded[8] = 1;
        assert_eq!(
            decode_attachment_bulk_record(&encoded),
            DecodedAttachmentBulkRecord::Unsupported
        );
        encoded[8] = 0;
        encoded[7] = 9;
        assert_eq!(
            decode_attachment_bulk_record(&encoded),
            DecodedAttachmentBulkRecord::Unsupported
        );
    }

    proptest! {
        #[test]
        fn arbitrary_input_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..70_000)) {
            let _ = decode_attachment_bulk_record(&bytes);
        }
    }
}
