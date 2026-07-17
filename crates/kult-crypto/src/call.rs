//! Per-call media encryption and replay protection (ADR-0013).

use alloc::vec::Vec;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{util, CryptoError, Result};

/// Media-stream framing magic and version.
pub const CALL_MEDIA_MAGIC: [u8; 4] = [b'K', b'C', b'M', 1];
/// Bytes before the encrypted media payload and authentication tag.
pub const CALL_MEDIA_HEADER_LEN: usize = 4 + 1 + 4 + 8 + 8 + 2;
/// Maximum Opus packet bytes accepted by the core.
pub const MAX_CALL_MEDIA_PAYLOAD_LEN: usize = 1_275;
/// Authentication tag bytes appended by XChaCha20-Poly1305.
pub const CALL_MEDIA_TAG_LEN: usize = 16;
/// Maximum canonical sealed media frame bytes.
pub const MAX_CALL_MEDIA_FRAME_LEN: usize =
    CALL_MEDIA_HEADER_LEN + MAX_CALL_MEDIA_PAYLOAD_LEN + CALL_MEDIA_TAG_LEN;
/// Rotate derived media keys after this many records in one direction.
pub const CALL_MEDIA_RECORDS_PER_KEY_PHASE: u64 = 4_096;
/// Replay-window width for authenticated records.
pub const CALL_MEDIA_REPLAY_WINDOW: u64 = 128;

const KIND_HELLO: u8 = 0;
const KIND_AUDIO: u8 = 1;
const CONTEXT_DOMAIN: &[u8] = b"komms-call-media-context-v1";
const I2R_MEDIA_INFO: &[u8] = b"komms-call-initiator-to-responder-media-v1";
const R2I_MEDIA_INFO: &[u8] = b"komms-call-responder-to-initiator-media-v1";
const I2R_HEADER_INFO: &[u8] = b"komms-call-initiator-to-responder-header-v1";
const R2I_HEADER_INFO: &[u8] = b"komms-call-responder-to-initiator-header-v1";
const PHASE_INFO: &[u8] = b"komms-call-media-key-phase-v1";
const NONCE_INFO: &[u8] = b"komms-call-media-nonce-v1";

/// Stable identities and exact physical devices bound into a call's keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallMediaContext {
    /// Random call id from the ratcheted offer.
    pub call_id: [u8; 16],
    /// Stable initiating account identity.
    pub initiator_account: [u8; 32],
    /// Stable responding account identity.
    pub responder_account: [u8; 32],
    /// Exact initiating device id.
    pub initiator_device: [u8; 32],
    /// Exact winning answering device id.
    pub responder_device: [u8; 32],
}

/// This endpoint's role in a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallRole {
    /// Device that created the offer.
    Initiator,
    /// Device whose answer won linked-device arbitration.
    Responder,
}

/// Authenticated decrypted media-record kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallMediaKind {
    /// Empty proof-of-key record that must precede audio in each direction.
    Hello,
    /// One bounded Opus packet.
    Audio,
}

/// One authenticated decrypted media record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallMediaFrame {
    /// Record kind.
    pub kind: CallMediaKind,
    /// Direction-local monotonically increasing sequence.
    pub sequence: u64,
    /// Sender capture timestamp in milliseconds; zero for hello.
    pub timestamp_ms: u64,
    /// Empty for hello; exact Opus packet bytes for audio.
    pub payload: Vec<u8>,
}

/// Direction-local media sealer. Secret fields are erased on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CallMediaSender {
    media_base: [u8; 32],
    header_base: [u8; 32],
    context_hash: [u8; 32],
    next_sequence: u64,
    hello_sent: bool,
}

impl CallMediaSender {
    /// Derive a sender from a fresh ratchet-carried call master secret.
    pub fn new(
        master_secret: &[u8; 32],
        context: &CallMediaContext,
        role: CallRole,
    ) -> Result<Self> {
        validate_context(master_secret, context)?;
        let context_hash = context_hash(context);
        let (media_info, header_info) = match role {
            CallRole::Initiator => (I2R_MEDIA_INFO, I2R_HEADER_INFO),
            CallRole::Responder => (R2I_MEDIA_INFO, R2I_HEADER_INFO),
        };
        Ok(Self {
            media_base: *util::hkdf32(Some(&context_hash), master_secret, media_info),
            header_base: *util::hkdf32(Some(&context_hash), master_secret, header_info),
            context_hash,
            next_sequence: 0,
            hello_sent: false,
        })
    }

    /// Seal the required empty proof-of-key record.
    pub fn seal_hello(&mut self) -> Result<Vec<u8>> {
        if self.hello_sent || self.next_sequence != 0 {
            return Err(CryptoError::InvalidMessage);
        }
        let sealed = self.seal_record(KIND_HELLO, 0, &[])?;
        self.hello_sent = true;
        Ok(sealed)
    }

    /// Seal one bounded Opus audio packet after the hello record.
    pub fn seal_audio(&mut self, timestamp_ms: u64, opus_packet: &[u8]) -> Result<Vec<u8>> {
        if !self.hello_sent
            || timestamp_ms == 0
            || opus_packet.is_empty()
            || opus_packet.len() > MAX_CALL_MEDIA_PAYLOAD_LEN
        {
            return Err(CryptoError::InvalidMessage);
        }
        self.seal_record(KIND_AUDIO, timestamp_ms, opus_packet)
    }

    fn seal_record(&mut self, kind: u8, timestamp_ms: u64, payload: &[u8]) -> Result<Vec<u8>> {
        let sequence = self.next_sequence;
        let phase = key_phase(sequence)?;
        let header = encode_header(kind, phase, sequence, timestamp_ms, payload.len())?;
        let key = phase_key(&self.media_base, phase);
        let nonce = media_nonce(&self.header_base, phase, sequence);
        let aad = associated_data(&self.context_hash, &header);
        let ciphertext = util::aead_encrypt_with_nonce(&key, &nonce, &aad, payload);
        self.next_sequence = sequence.checked_add(1).ok_or(CryptoError::InvalidMessage)?;
        let mut out = Vec::with_capacity(header.len() + ciphertext.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }
}

/// Direction-local media opener with bounded replay state. Secrets are erased
/// on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CallMediaReceiver {
    media_base: [u8; 32],
    header_base: [u8; 32],
    context_hash: [u8; 32],
    highest_sequence: u64,
    replay_bitmap: u128,
    has_sequence: bool,
    hello_received: bool,
}

impl CallMediaReceiver {
    /// Derive a receiver for media sent by the opposite call role.
    pub fn new(
        master_secret: &[u8; 32],
        context: &CallMediaContext,
        role: CallRole,
    ) -> Result<Self> {
        validate_context(master_secret, context)?;
        let context_hash = context_hash(context);
        let (media_info, header_info) = match role {
            CallRole::Initiator => (R2I_MEDIA_INFO, R2I_HEADER_INFO),
            CallRole::Responder => (I2R_MEDIA_INFO, I2R_HEADER_INFO),
        };
        Ok(Self {
            media_base: *util::hkdf32(Some(&context_hash), master_secret, media_info),
            header_base: *util::hkdf32(Some(&context_hash), master_secret, header_info),
            context_hash,
            highest_sequence: 0,
            replay_bitmap: 0,
            has_sequence: false,
            hello_received: false,
        })
    }

    /// Authenticate and open one complete canonical media record.
    pub fn open(&mut self, bytes: &[u8]) -> Result<CallMediaFrame> {
        let parsed = parse_header(bytes)?;
        if parsed.phase != key_phase(parsed.sequence)? {
            return Err(CryptoError::InvalidMessage);
        }
        match parsed.kind {
            KIND_HELLO
                if parsed.sequence == 0
                    && parsed.timestamp_ms == 0
                    && parsed.payload_len == 0
                    && !self.hello_received => {}
            KIND_AUDIO
                if self.hello_received
                    && parsed.sequence > 0
                    && parsed.timestamp_ms > 0
                    && parsed.payload_len > 0 => {}
            _ => return Err(CryptoError::InvalidMessage),
        }
        let replay = replay_after(
            self.has_sequence,
            self.highest_sequence,
            self.replay_bitmap,
            parsed.sequence,
        )?;
        let header = &bytes[..CALL_MEDIA_HEADER_LEN];
        let ciphertext = &bytes[CALL_MEDIA_HEADER_LEN..];
        let key = phase_key(&self.media_base, parsed.phase);
        let nonce = media_nonce(&self.header_base, parsed.phase, parsed.sequence);
        let aad = associated_data(&self.context_hash, header);
        let payload = util::aead_decrypt_with_nonce(&key, &nonce, &aad, ciphertext)?;
        if payload.len() != parsed.payload_len {
            return Err(CryptoError::InvalidMessage);
        }
        self.has_sequence = true;
        self.highest_sequence = replay.0;
        self.replay_bitmap = replay.1;
        let kind = if parsed.kind == KIND_HELLO {
            self.hello_received = true;
            CallMediaKind::Hello
        } else {
            CallMediaKind::Audio
        };
        Ok(CallMediaFrame {
            kind,
            sequence: parsed.sequence,
            timestamp_ms: parsed.timestamp_ms,
            payload,
        })
    }
}

struct ParsedHeader {
    kind: u8,
    phase: u32,
    sequence: u64,
    timestamp_ms: u64,
    payload_len: usize,
}

fn validate_context(master_secret: &[u8; 32], context: &CallMediaContext) -> Result<()> {
    if all_zero(master_secret)
        || all_zero(&context.call_id)
        || all_zero(&context.initiator_account)
        || all_zero(&context.responder_account)
        || all_zero(&context.initiator_device)
        || all_zero(&context.responder_device)
    {
        return Err(CryptoError::InvalidKey);
    }
    Ok(())
}

fn context_hash(context: &CallMediaContext) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(CONTEXT_DOMAIN.len() + 16 + 32 * 4);
    bytes.extend_from_slice(CONTEXT_DOMAIN);
    bytes.extend_from_slice(&context.call_id);
    bytes.extend_from_slice(&context.initiator_account);
    bytes.extend_from_slice(&context.responder_account);
    bytes.extend_from_slice(&context.initiator_device);
    bytes.extend_from_slice(&context.responder_device);
    *blake3::hash(&bytes).as_bytes()
}

fn key_phase(sequence: u64) -> Result<u32> {
    u32::try_from(sequence / CALL_MEDIA_RECORDS_PER_KEY_PHASE)
        .map_err(|_| CryptoError::InvalidMessage)
}

fn phase_key(base: &[u8; 32], phase: u32) -> Zeroizing<[u8; 32]> {
    util::hkdf32(Some(&phase.to_le_bytes()), base, PHASE_INFO)
}

fn media_nonce(header_base: &[u8; 32], phase: u32, sequence: u64) -> [u8; util::NONCE_LEN] {
    let mut info = [0u8; NONCE_INFO.len() + 4 + 8];
    info[..NONCE_INFO.len()].copy_from_slice(NONCE_INFO);
    info[NONCE_INFO.len()..NONCE_INFO.len() + 4].copy_from_slice(&phase.to_le_bytes());
    info[NONCE_INFO.len() + 4..].copy_from_slice(&sequence.to_le_bytes());
    let mut nonce = [0u8; util::NONCE_LEN];
    util::hkdf_expand(None, header_base, &info, &mut nonce);
    nonce
}

fn encode_header(
    kind: u8,
    phase: u32,
    sequence: u64,
    timestamp_ms: u64,
    payload_len: usize,
) -> Result<[u8; CALL_MEDIA_HEADER_LEN]> {
    let payload_len = u16::try_from(payload_len).map_err(|_| CryptoError::InvalidMessage)?;
    let mut header = [0u8; CALL_MEDIA_HEADER_LEN];
    header[..4].copy_from_slice(&CALL_MEDIA_MAGIC);
    header[4] = kind;
    header[5..9].copy_from_slice(&phase.to_le_bytes());
    header[9..17].copy_from_slice(&sequence.to_le_bytes());
    header[17..25].copy_from_slice(&timestamp_ms.to_le_bytes());
    header[25..27].copy_from_slice(&payload_len.to_le_bytes());
    Ok(header)
}

fn parse_header(bytes: &[u8]) -> Result<ParsedHeader> {
    if bytes.len() < CALL_MEDIA_HEADER_LEN + CALL_MEDIA_TAG_LEN
        || bytes.len() > MAX_CALL_MEDIA_FRAME_LEN
        || bytes[..4] != CALL_MEDIA_MAGIC
    {
        return Err(CryptoError::InvalidMessage);
    }
    let kind = bytes[4];
    let phase = u32::from_le_bytes(bytes[5..9].try_into().expect("fixed slice"));
    let sequence = u64::from_le_bytes(bytes[9..17].try_into().expect("fixed slice"));
    let timestamp_ms = u64::from_le_bytes(bytes[17..25].try_into().expect("fixed slice"));
    let payload_len = u16::from_le_bytes(bytes[25..27].try_into().expect("fixed slice")) as usize;
    if payload_len > MAX_CALL_MEDIA_PAYLOAD_LEN
        || bytes.len() != CALL_MEDIA_HEADER_LEN + payload_len + CALL_MEDIA_TAG_LEN
    {
        return Err(CryptoError::InvalidMessage);
    }
    Ok(ParsedHeader {
        kind,
        phase,
        sequence,
        timestamp_ms,
        payload_len,
    })
}

fn associated_data(context_hash: &[u8; 32], header: &[u8]) -> [u8; 32 + CALL_MEDIA_HEADER_LEN] {
    let mut aad = [0u8; 32 + CALL_MEDIA_HEADER_LEN];
    aad[..32].copy_from_slice(context_hash);
    aad[32..].copy_from_slice(header);
    aad
}

fn replay_after(
    has_sequence: bool,
    highest: u64,
    bitmap: u128,
    sequence: u64,
) -> Result<(u64, u128)> {
    if !has_sequence {
        return Ok((sequence, 1));
    }
    if sequence > highest {
        let shift = sequence - highest;
        let next = if shift >= CALL_MEDIA_REPLAY_WINDOW {
            1
        } else {
            (bitmap << shift) | 1
        };
        return Ok((sequence, next));
    }
    let behind = highest - sequence;
    if behind >= CALL_MEDIA_REPLAY_WINDOW || bitmap & (1u128 << behind) != 0 {
        return Err(CryptoError::MessageAuthentication);
    }
    Ok((highest, bitmap | (1u128 << behind)))
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> CallMediaContext {
        CallMediaContext {
            call_id: [1; 16],
            initiator_account: [2; 32],
            responder_account: [3; 32],
            initiator_device: [4; 32],
            responder_device: [5; 32],
        }
    }

    #[test]
    fn both_directions_require_hello_then_round_trip_audio() {
        let secret = [9; 32];
        for (sender_role, receiver_role) in [
            (CallRole::Initiator, CallRole::Responder),
            (CallRole::Responder, CallRole::Initiator),
        ] {
            let mut sender = CallMediaSender::new(&secret, &context(), sender_role).unwrap();
            let mut receiver = CallMediaReceiver::new(&secret, &context(), receiver_role).unwrap();
            assert!(sender.seal_audio(1, b"opus").is_err());
            let hello = sender.seal_hello().unwrap();
            assert_eq!(receiver.open(&hello).unwrap().kind, CallMediaKind::Hello);
            let audio = sender.seal_audio(20, b"opus").unwrap();
            assert_eq!(
                receiver.open(&audio).unwrap(),
                CallMediaFrame {
                    kind: CallMediaKind::Audio,
                    sequence: 1,
                    timestamp_ms: 20,
                    payload: b"opus".to_vec(),
                }
            );
        }
    }

    #[test]
    fn tamper_replay_wrong_role_and_wrong_context_fail_closed() {
        let secret = [9; 32];
        let mut sender = CallMediaSender::new(&secret, &context(), CallRole::Initiator).unwrap();
        let hello = sender.seal_hello().unwrap();
        let mut tampered = hello.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let mut receiver =
            CallMediaReceiver::new(&secret, &context(), CallRole::Responder).unwrap();
        assert_eq!(
            receiver.open(&tampered),
            Err(CryptoError::MessageAuthentication)
        );
        assert!(receiver.open(&hello).is_ok());
        assert_eq!(receiver.open(&hello), Err(CryptoError::InvalidMessage));

        let mut wrong_role =
            CallMediaReceiver::new(&secret, &context(), CallRole::Initiator).unwrap();
        assert_eq!(
            wrong_role.open(&hello),
            Err(CryptoError::MessageAuthentication)
        );
        let mut changed = context();
        changed.call_id[0] ^= 1;
        let mut wrong_call =
            CallMediaReceiver::new(&secret, &changed, CallRole::Responder).unwrap();
        assert_eq!(
            wrong_call.open(&hello),
            Err(CryptoError::MessageAuthentication)
        );
    }

    #[test]
    fn key_phase_rotation_and_replay_window_are_bounded() {
        let secret = [7; 32];
        let mut sender = CallMediaSender::new(&secret, &context(), CallRole::Initiator).unwrap();
        let mut receiver =
            CallMediaReceiver::new(&secret, &context(), CallRole::Responder).unwrap();
        receiver.open(&sender.seal_hello().unwrap()).unwrap();
        let mut last = Vec::new();
        for sequence in 1..=CALL_MEDIA_RECORDS_PER_KEY_PHASE {
            let frame = sender.seal_audio(sequence, b"x").unwrap();
            let opened = receiver.open(&frame).unwrap();
            assert_eq!(opened.sequence, sequence);
            last = frame;
        }
        assert_eq!(
            receiver.open(&last),
            Err(CryptoError::MessageAuthentication)
        );
    }

    #[test]
    fn malformed_bounds_and_zero_context_are_rejected() {
        let mut zero = context();
        zero.responder_device.fill(0);
        assert!(CallMediaSender::new(&[9; 32], &zero, CallRole::Initiator).is_err());
        assert!(CallMediaSender::new(&[0; 32], &context(), CallRole::Initiator).is_err());
        let mut receiver =
            CallMediaReceiver::new(&[9; 32], &context(), CallRole::Responder).unwrap();
        assert!(receiver.open(&[]).is_err());
        assert!(receiver
            .open(&vec![0; MAX_CALL_MEDIA_FRAME_LEN + 1])
            .is_err());
    }
}
