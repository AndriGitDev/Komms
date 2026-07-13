//! Canonical encrypted content-capability controls (ADR-0014).

use alloc::vec::Vec;

use crate::{ProtocolError, Result};

/// Prefix for capability controls multiplexed over the encrypted receipt lane.
pub const CAPABILITY_MAGIC: [u8; 6] = [0x00, 0x00, 0xff, b'K', b'C', b'C'];
/// Current capability control format version.
pub const CAPABILITY_CONTROL_VERSION: u8 = 1;
/// Maximum content formats in one capability snapshot.
pub const MAX_CAPABILITY_FORMATS: usize = 4;
/// Maximum kinds advertised for one content format.
pub const MAX_CAPABILITY_KINDS: usize = 64;

/// Kinds supported for one content framing version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatCapabilities {
    /// Content framing version.
    pub format_version: u8,
    /// Strictly increasing, unique supported content kinds.
    pub kinds: Vec<u16>,
}

/// A complete authenticated capability snapshot for one peer session.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapabilityControl {
    /// Strictly increasing, unique content-format entries.
    pub formats: Vec<FormatCapabilities>,
}

impl CapabilityControl {
    /// Encode a canonical capability control.
    ///
    /// Entries must already be strictly sorted and unique so callers cannot
    /// accidentally authenticate multiple byte encodings for one snapshot.
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_formats(&self.formats)?;

        let payload_len = self
            .formats
            .iter()
            .map(|format| 2 + format.kinds.len() * 2)
            .sum::<usize>();
        let mut bytes = Vec::with_capacity(CAPABILITY_MAGIC.len() + 2 + payload_len);
        bytes.extend_from_slice(&CAPABILITY_MAGIC);
        bytes.push(CAPABILITY_CONTROL_VERSION);
        bytes.push(self.formats.len() as u8);
        for format in &self.formats {
            bytes.push(format.format_version);
            bytes.push(format.kinds.len() as u8);
            for kind in &format.kinds {
                bytes.extend_from_slice(&kind.to_le_bytes());
            }
        }
        Ok(bytes)
    }

    /// Decode and validate one complete canonical capability control.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < CAPABILITY_MAGIC.len() + 2
            || !is_capability_control(bytes)
            || bytes[6] != CAPABILITY_CONTROL_VERSION
        {
            return Err(ProtocolError::Malformed);
        }

        let format_count = bytes[7] as usize;
        if format_count > MAX_CAPABILITY_FORMATS {
            return Err(ProtocolError::Malformed);
        }

        let mut offset = 8usize;
        let mut formats = Vec::with_capacity(format_count);
        for _ in 0..format_count {
            let header = bytes
                .get(offset..offset + 2)
                .ok_or(ProtocolError::Malformed)?;
            let format_version = header[0];
            let kind_count = header[1] as usize;
            offset += 2;
            if format_version == 0 || kind_count > MAX_CAPABILITY_KINDS {
                return Err(ProtocolError::Malformed);
            }
            let kinds_len = kind_count.checked_mul(2).ok_or(ProtocolError::Malformed)?;
            let encoded_kinds = bytes
                .get(offset..offset + kinds_len)
                .ok_or(ProtocolError::Malformed)?;
            let mut kinds = Vec::with_capacity(kind_count);
            for pair in encoded_kinds.chunks_exact(2) {
                kinds.push(u16::from_le_bytes([pair[0], pair[1]]));
            }
            offset += kinds_len;
            formats.push(FormatCapabilities {
                format_version,
                kinds,
            });
        }

        if offset != bytes.len() {
            return Err(ProtocolError::Malformed);
        }
        validate_formats(&formats)?;
        Ok(Self { formats })
    }

    /// Return whether this snapshot advertises one exact format and kind.
    pub fn supports(&self, format_version: u8, kind: u16) -> bool {
        self.formats
            .binary_search_by_key(&format_version, |format| format.format_version)
            .ok()
            .and_then(|index| self.formats[index].kinds.binary_search(&kind).ok())
            .is_some()
    }
}

/// Return whether decrypted receipt-lane bytes begin with capability magic.
pub fn is_capability_control(bytes: &[u8]) -> bool {
    bytes.starts_with(&CAPABILITY_MAGIC)
}

fn validate_formats(formats: &[FormatCapabilities]) -> Result<()> {
    if formats.len() > MAX_CAPABILITY_FORMATS {
        return Err(ProtocolError::TooLarge);
    }

    let mut previous_format = None;
    for format in formats {
        if format.format_version == 0
            || previous_format.is_some_and(|previous| previous >= format.format_version)
        {
            return Err(ProtocolError::Malformed);
        }
        previous_format = Some(format.format_version);
        if format.kinds.len() > MAX_CAPABILITY_KINDS {
            return Err(ProtocolError::TooLarge);
        }

        let mut previous_kind = None;
        for &kind in &format.kinds {
            if kind == 0 || previous_kind.is_some_and(|previous| previous >= kind) {
                return Err(ProtocolError::Malformed);
            }
            previous_kind = Some(kind);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ReceiptPayload, CONTENT_FORMAT_V1, CONTENT_KIND_TEXT};
    use proptest::prelude::*;

    fn text_control() -> CapabilityControl {
        CapabilityControl {
            formats: vec![FormatCapabilities {
                format_version: CONTENT_FORMAT_V1,
                kinds: vec![CONTENT_KIND_TEXT],
            }],
        }
    }

    #[test]
    fn capability_golden_vector_and_old_receipt_compatibility() {
        let bytes = text_control().encode().unwrap();
        assert_eq!(
            bytes,
            [0x00, 0x00, 0xff, 0x4b, 0x43, 0x43, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00]
        );
        assert_eq!(CapabilityControl::decode(&bytes).unwrap(), text_control());
        assert!(is_capability_control(&bytes));

        // Shipped Postcard receipt decoding ignores the unused suffix after
        // the canonical two-byte empty receipt. Old endpoints therefore see
        // a harmless empty receipt and never surface a chat message.
        assert_eq!(
            ReceiptPayload::decode(&bytes).unwrap(),
            ReceiptPayload::default()
        );
    }

    #[test]
    fn canonical_order_counts_and_trailing_bytes_are_enforced() {
        for formats in [
            vec![
                FormatCapabilities {
                    format_version: 2,
                    kinds: vec![1],
                },
                FormatCapabilities {
                    format_version: 1,
                    kinds: vec![1],
                },
            ],
            vec![FormatCapabilities {
                format_version: 1,
                kinds: vec![2, 1],
            }],
            vec![FormatCapabilities {
                format_version: 1,
                kinds: vec![1, 1],
            }],
            vec![FormatCapabilities {
                format_version: 0,
                kinds: vec![1],
            }],
            vec![FormatCapabilities {
                format_version: 1,
                kinds: vec![0],
            }],
        ] {
            assert_eq!(
                CapabilityControl { formats }.encode(),
                Err(ProtocolError::Malformed)
            );
        }

        let mut trailing = text_control().encode().unwrap();
        trailing.push(0);
        assert_eq!(
            CapabilityControl::decode(&trailing),
            Err(ProtocolError::Malformed)
        );

        let mut too_many = text_control().encode().unwrap();
        too_many[9] = (MAX_CAPABILITY_KINDS + 1) as u8;
        assert_eq!(
            CapabilityControl::decode(&too_many),
            Err(ProtocolError::Malformed)
        );
    }

    #[test]
    fn supports_exact_format_and_kind() {
        let control = CapabilityControl {
            formats: vec![
                FormatCapabilities {
                    format_version: 1,
                    kinds: vec![1, 3],
                },
                FormatCapabilities {
                    format_version: 2,
                    kinds: vec![7],
                },
            ],
        };
        assert!(control.supports(1, 1));
        assert!(control.supports(1, 3));
        assert!(!control.supports(1, 2));
        assert!(!control.supports(3, 1));
    }

    proptest! {
        #[test]
        fn arbitrary_input_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
            let _ = CapabilityControl::decode(&bytes);
        }

        #[test]
        fn sorted_unique_snapshots_round_trip(
            mut formats in proptest::collection::vec(
                (1u8..=u8::MAX, proptest::collection::btree_set(1u16..=u16::MAX, 0..=8)),
                0..=MAX_CAPABILITY_FORMATS,
            )
        ) {
            formats.sort_unstable_by_key(|(version, _)| *version);
            formats.dedup_by_key(|(version, _)| *version);
            let control = CapabilityControl {
                formats: formats.into_iter().map(|(format_version, kinds)| FormatCapabilities {
                    format_version,
                    kinds: kinds.into_iter().collect(),
                }).collect(),
            };
            let encoded = control.encode().unwrap();
            prop_assert_eq!(CapabilityControl::decode(&encoded).unwrap(), control);
        }
    }
}
