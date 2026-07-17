//! Canonical transient call-control payloads (ADR-0013).

use alloc::vec::Vec;

use crate::{ProtocolError, Result};

/// Current call-control payload version.
pub const CALL_CONTROL_VERSION: u8 = 1;
/// Bytes shared by every call-control payload.
pub const CALL_CONTROL_HEADER_LEN: usize = 1 + 1 + 16 + 32 + 8;
/// Bytes in a control carrying a call master secret or responder device.
pub const CALL_CONTROL_BOUND_LEN: usize = CALL_CONTROL_HEADER_LEN + 32;
/// Hangup additionally authenticates why this exact device pair is ending.
pub const CALL_CONTROL_HANGUP_LEN: usize = CALL_CONTROL_BOUND_LEN + 1;
/// Maximum canonical call-control payload size.
pub const MAX_CALL_CONTROL_LEN: usize = CALL_CONTROL_HANGUP_LEN;

const OP_OFFER: u8 = 1;
const OP_ANSWER: u8 = 2;
const OP_DECLINE: u8 = 3;
const OP_BUSY: u8 = 4;
const OP_CANCEL: u8 = 5;
const OP_HANGUP: u8 = 6;

/// Authenticated reason carried by one `Hangup` operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallHangupReason {
    /// The locally selected device pair ended before or during media.
    Ended,
    /// Another linked recipient device's earlier valid answer won.
    AnsweredElsewhere,
}

/// One authenticated transient call-state transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallControl {
    /// Start a call and convey a fresh secret inside the pairwise ratchet.
    Offer {
        /// Random id shared by every transition for this call.
        call_id: [u8; 16],
        /// Exact physical device that initiated the call.
        initiator_device: [u8; 32],
        /// Absolute UTC expiry for accepting this offer.
        expires_at: u64,
        /// Fresh call master secret; never derived from ratchet state.
        master_secret: [u8; 32],
    },
    /// Accept an offer from one exact physical recipient device.
    Answer {
        /// Random id from the offer.
        call_id: [u8; 16],
        /// Exact initiating physical device.
        initiator_device: [u8; 32],
        /// Exact answering physical device.
        responder_device: [u8; 32],
        /// Absolute UTC offer expiry copied unchanged.
        expires_at: u64,
    },
    /// Decline an offer from one exact physical recipient device.
    Decline {
        /// Random id from the offer.
        call_id: [u8; 16],
        /// Exact initiating physical device.
        initiator_device: [u8; 32],
        /// Exact declining physical device.
        responder_device: [u8; 32],
        /// Absolute UTC offer expiry copied unchanged.
        expires_at: u64,
    },
    /// Refuse an offer because this recipient device is already occupied.
    Busy {
        /// Random id from the offer.
        call_id: [u8; 16],
        /// Exact initiating physical device.
        initiator_device: [u8; 32],
        /// Exact busy physical device.
        responder_device: [u8; 32],
        /// Absolute UTC offer expiry copied unchanged.
        expires_at: u64,
    },
    /// Cancel an unanswered offer on every recipient device.
    Cancel {
        /// Random id from the offer.
        call_id: [u8; 16],
        /// Exact initiating physical device.
        initiator_device: [u8; 32],
        /// Absolute UTC offer expiry copied unchanged.
        expires_at: u64,
    },
    /// End the exact device pair selected by the winning answer.
    Hangup {
        /// Random id from the offer.
        call_id: [u8; 16],
        /// Exact initiating physical device.
        initiator_device: [u8; 32],
        /// Exact answering physical device.
        responder_device: [u8; 32],
        /// Absolute UTC offer expiry copied unchanged.
        expires_at: u64,
        /// Whether the selected pair ended or this device lost arbitration.
        reason: CallHangupReason,
    },
}

impl CallControl {
    /// Return the call id common to every operation.
    pub fn call_id(&self) -> [u8; 16] {
        match self {
            Self::Offer { call_id, .. }
            | Self::Answer { call_id, .. }
            | Self::Decline { call_id, .. }
            | Self::Busy { call_id, .. }
            | Self::Cancel { call_id, .. }
            | Self::Hangup { call_id, .. } => *call_id,
        }
    }

    /// Return the physical device that initiated the call.
    pub fn initiator_device(&self) -> [u8; 32] {
        match self {
            Self::Offer {
                initiator_device, ..
            }
            | Self::Answer {
                initiator_device, ..
            }
            | Self::Decline {
                initiator_device, ..
            }
            | Self::Busy {
                initiator_device, ..
            }
            | Self::Cancel {
                initiator_device, ..
            }
            | Self::Hangup {
                initiator_device, ..
            } => *initiator_device,
        }
    }

    /// Return the absolute expiry copied from the offer.
    pub fn expires_at(&self) -> u64 {
        match self {
            Self::Offer { expires_at, .. }
            | Self::Answer { expires_at, .. }
            | Self::Decline { expires_at, .. }
            | Self::Busy { expires_at, .. }
            | Self::Cancel { expires_at, .. }
            | Self::Hangup { expires_at, .. } => *expires_at,
        }
    }
}

/// Total classification of authenticated call-control payload bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodedCallControl {
    /// Canonical supported control.
    Control(CallControl),
    /// A newer payload version or operation that this endpoint cannot apply.
    Unsupported,
    /// Bytes violate the canonical call-control shape.
    Malformed,
}

/// Encode one canonical call-control payload.
pub fn encode_call_control_payload(control: &CallControl) -> Result<Vec<u8>> {
    let (op, call_id, initiator, expires_at, bound, hangup_reason) = match control {
        CallControl::Offer {
            call_id,
            initiator_device,
            expires_at,
            master_secret,
        } => (
            OP_OFFER,
            call_id,
            initiator_device,
            expires_at,
            Some(master_secret),
            None,
        ),
        CallControl::Answer {
            call_id,
            initiator_device,
            responder_device,
            expires_at,
        } => (
            OP_ANSWER,
            call_id,
            initiator_device,
            expires_at,
            Some(responder_device),
            None,
        ),
        CallControl::Decline {
            call_id,
            initiator_device,
            responder_device,
            expires_at,
        } => (
            OP_DECLINE,
            call_id,
            initiator_device,
            expires_at,
            Some(responder_device),
            None,
        ),
        CallControl::Busy {
            call_id,
            initiator_device,
            responder_device,
            expires_at,
        } => (
            OP_BUSY,
            call_id,
            initiator_device,
            expires_at,
            Some(responder_device),
            None,
        ),
        CallControl::Cancel {
            call_id,
            initiator_device,
            expires_at,
        } => (OP_CANCEL, call_id, initiator_device, expires_at, None, None),
        CallControl::Hangup {
            call_id,
            initiator_device,
            responder_device,
            expires_at,
            reason,
        } => (
            OP_HANGUP,
            call_id,
            initiator_device,
            expires_at,
            Some(responder_device),
            Some(reason),
        ),
    };
    if all_zero(call_id)
        || all_zero(initiator)
        || expires_at == &0
        || bound.is_some_and(|value| all_zero(value))
    {
        return Err(ProtocolError::Malformed);
    }
    let mut out = Vec::with_capacity(
        CALL_CONTROL_HEADER_LEN + bound.map_or(0, |_| 32) + hangup_reason.map_or(0, |_| 1),
    );
    out.push(CALL_CONTROL_VERSION);
    out.push(op);
    out.extend_from_slice(call_id);
    out.extend_from_slice(initiator);
    out.extend_from_slice(&expires_at.to_le_bytes());
    if let Some(bound) = bound {
        out.extend_from_slice(bound);
    }
    if let Some(reason) = hangup_reason {
        out.push(match reason {
            CallHangupReason::Ended => 0,
            CallHangupReason::AnsweredElsewhere => 1,
        });
    }
    Ok(out)
}

/// Decode call-control payload bytes without allocating.
pub fn decode_call_control_payload(bytes: &[u8]) -> DecodedCallControl {
    if bytes.len() < 2 || bytes.len() > MAX_CALL_CONTROL_LEN {
        return DecodedCallControl::Malformed;
    }
    if bytes[0] != CALL_CONTROL_VERSION {
        return DecodedCallControl::Unsupported;
    }
    let op = bytes[1];
    if !matches!(op, OP_OFFER..=OP_HANGUP) {
        return DecodedCallControl::Unsupported;
    }
    let expected_len = match op {
        OP_CANCEL => CALL_CONTROL_HEADER_LEN,
        OP_HANGUP => CALL_CONTROL_HANGUP_LEN,
        _ => CALL_CONTROL_BOUND_LEN,
    };
    if bytes.len() != expected_len {
        return DecodedCallControl::Malformed;
    }
    let mut call_id = [0u8; 16];
    call_id.copy_from_slice(&bytes[2..18]);
    let mut initiator_device = [0u8; 32];
    initiator_device.copy_from_slice(&bytes[18..50]);
    let expires_at = u64::from_le_bytes(bytes[50..58].try_into().expect("fixed slice"));
    if all_zero(&call_id) || all_zero(&initiator_device) || expires_at == 0 {
        return DecodedCallControl::Malformed;
    }
    if op == OP_CANCEL {
        return DecodedCallControl::Control(CallControl::Cancel {
            call_id,
            initiator_device,
            expires_at,
        });
    }
    let mut bound = [0u8; 32];
    bound.copy_from_slice(&bytes[58..90]);
    if all_zero(&bound) {
        return DecodedCallControl::Malformed;
    }
    let control = match op {
        OP_OFFER => CallControl::Offer {
            call_id,
            initiator_device,
            expires_at,
            master_secret: bound,
        },
        OP_ANSWER => CallControl::Answer {
            call_id,
            initiator_device,
            responder_device: bound,
            expires_at,
        },
        OP_DECLINE => CallControl::Decline {
            call_id,
            initiator_device,
            responder_device: bound,
            expires_at,
        },
        OP_BUSY => CallControl::Busy {
            call_id,
            initiator_device,
            responder_device: bound,
            expires_at,
        },
        OP_HANGUP => CallControl::Hangup {
            call_id,
            initiator_device,
            responder_device: bound,
            expires_at,
            reason: match bytes[90] {
                0 => CallHangupReason::Ended,
                1 => CallHangupReason::AnsweredElsewhere,
                _ => return DecodedCallControl::Malformed,
            },
        },
        _ => unreachable!("operation checked above"),
    };
    DecodedCallControl::Control(control)
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn controls() -> [CallControl; 6] {
        [
            CallControl::Offer {
                call_id: [1; 16],
                initiator_device: [2; 32],
                expires_at: 99,
                master_secret: [3; 32],
            },
            CallControl::Answer {
                call_id: [1; 16],
                initiator_device: [2; 32],
                responder_device: [4; 32],
                expires_at: 99,
            },
            CallControl::Decline {
                call_id: [1; 16],
                initiator_device: [2; 32],
                responder_device: [4; 32],
                expires_at: 99,
            },
            CallControl::Busy {
                call_id: [1; 16],
                initiator_device: [2; 32],
                responder_device: [4; 32],
                expires_at: 99,
            },
            CallControl::Cancel {
                call_id: [1; 16],
                initiator_device: [2; 32],
                expires_at: 99,
            },
            CallControl::Hangup {
                call_id: [1; 16],
                initiator_device: [2; 32],
                responder_device: [4; 32],
                expires_at: 99,
                reason: CallHangupReason::Ended,
            },
        ]
    }

    #[test]
    fn every_operation_round_trips_canonically() {
        for control in controls() {
            let bytes = encode_call_control_payload(&control).unwrap();
            assert_eq!(
                decode_call_control_payload(&bytes),
                DecodedCallControl::Control(control)
            );
        }
    }

    #[test]
    fn unknowns_lengths_zero_fields_and_trailing_bytes_fail_closed() {
        let mut canonical = encode_call_control_payload(&controls()[0]).unwrap();
        canonical[0] = 2;
        assert_eq!(
            decode_call_control_payload(&canonical),
            DecodedCallControl::Unsupported
        );
        canonical[0] = CALL_CONTROL_VERSION;
        canonical[1] = 99;
        assert_eq!(
            decode_call_control_payload(&canonical),
            DecodedCallControl::Unsupported
        );
        for range in [2..18, 18..50, 58..90] {
            let mut invalid = encode_call_control_payload(&controls()[0]).unwrap();
            invalid[range].fill(0);
            assert_eq!(
                decode_call_control_payload(&invalid),
                DecodedCallControl::Malformed
            );
        }
        let mut trailing = encode_call_control_payload(&controls()[0]).unwrap();
        trailing.push(0);
        assert_eq!(
            decode_call_control_payload(&trailing),
            DecodedCallControl::Malformed
        );
        let mut hangup = encode_call_control_payload(&controls()[5]).unwrap();
        assert_eq!(hangup.len(), CALL_CONTROL_HANGUP_LEN);
        *hangup.last_mut().expect("reason") = 2;
        assert_eq!(
            decode_call_control_payload(&hangup),
            DecodedCallControl::Malformed
        );
    }

    proptest! {
        #[test]
        fn arbitrary_input_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = decode_call_control_payload(&bytes);
        }
    }
}
