//! Transient account-aware call signaling (ADR-0013).

use std::collections::{HashSet, VecDeque};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::task::noop_waker_ref;
use futures::{AsyncRead, AsyncWrite};
use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use kult_crypto::{
    call_media_record_len, CallMediaContext, CallMediaKind, CallMediaReceiver, CallMediaSender,
    CallRole, CALL_MEDIA_HEADER_LEN, MAX_CALL_MEDIA_FRAME_LEN,
};
use kult_protocol::{
    encode_call_control, pad, CallControl, CallHangupReason, Envelope, EnvelopeKind, MailboxKey,
};
use kult_store::{QueueClass, QueueItem};
use kult_transport::CallStream;

use crate::{
    delivery_token, epoch_day, CallAudioFrame, CallAvailability, CallDirection, CallEndReason,
    CallInfo, CallPhase, CallUnavailableReason, CarrierCapability, Event, Node, NodeError, Result,
    CONTENT_FORMAT_V1, CONTENT_KIND_CALL_CONTROL,
};

/// Offers are short-lived and never become delayed-message work.
pub const CALL_OFFER_LIFETIME_SECS: u64 = 60;
/// Reject remote offers that claim an unexpectedly distant deadline.
pub const MAX_CALL_OFFER_LIFETIME_SECS: u64 = 90;
/// Keep terminal render state briefly, while retaining no secret bytes.
const TERMINAL_CALL_RETENTION_SECS: u64 = 300;
/// Bound all transient call state, including recently ended rows.
const MAX_TRANSIENT_CALLS: usize = 32;
/// At most 160 ms of 20 ms capture packets wait for the stream writer.
const MAX_QUEUED_AUDIO_FRAMES: usize = 8;
/// A packet that has not entered the stream by this age has missed playout.
const MAX_QUEUED_AUDIO_AGE: Duration = Duration::from_millis(200);
/// Begin native playout with a small fixed cushion.
const JITTER_START_FRAMES: usize = 3;
/// Never let receiver buffering grow latency without bound.
const JITTER_MAX_FRAMES: usize = 6;
/// Bound unauthenticated or malformed bytes before a canonical record forms.
const MAX_MEDIA_READ_BUFFER: usize = MAX_CALL_MEDIA_FRAME_LEN * 2;
/// A few invalid stream attempts may race an honest inbound stream, but an
/// unbounded sequence must not keep transient state alive forever.
const MAX_MEDIA_HANDSHAKE_FAILURES: u8 = 3;
/// A closed active media stream may be the peer intentionally hanging up;
/// leave one ordinary control heartbeat for its authenticated Hangup before
/// classifying the same EOF as route loss.
const MEDIA_ROUTE_LOSS_GRACE_SECS: u64 = 1;

struct PendingMediaWrite {
    bytes: Vec<u8>,
    offset: usize,
    audio: bool,
    queued_at: Instant,
}

struct CallMediaState {
    stream: CallStream,
    sender: CallMediaSender,
    receiver: CallMediaReceiver,
    writes: VecDeque<PendingMediaWrite>,
    reads: Vec<u8>,
    jitter: VecDeque<CallAudioFrame>,
    hello_written: bool,
    hello_received: bool,
    playout_started: bool,
}

pub(crate) struct ActiveCall {
    info: CallInfo,
    master_secret: Option<Zeroizing<[u8; 32]>>,
    offered_devices: Vec<[u8; 32]>,
    negative_responses: HashSet<[u8; 32]>,
    saw_decline: bool,
    updated_at: u64,
    media: Option<CallMediaState>,
    media_failures: u8,
    media_lost_at: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MediaFailure {
    Link,
    Authentication,
}

impl CallMediaState {
    fn new(
        stream: CallStream,
        secret: &[u8; 32],
        context: &CallMediaContext,
        role: CallRole,
    ) -> Result<Self> {
        let mut sender = CallMediaSender::new(secret, context, role)?;
        let receiver = CallMediaReceiver::new(secret, context, role)?;
        let hello = sender.seal_hello()?;
        let mut writes = VecDeque::new();
        writes.push_back(PendingMediaWrite {
            bytes: hello,
            offset: 0,
            audio: false,
            queued_at: Instant::now(),
        });
        Ok(Self {
            stream,
            sender,
            receiver,
            writes,
            reads: Vec::new(),
            jitter: VecDeque::new(),
            hello_written: false,
            hello_received: false,
            playout_started: false,
        })
    }

    fn queue_audio(&mut self, timestamp_ms: u64, opus_packet: &[u8]) -> Result<bool> {
        self.drop_stale_audio();
        if self.writes.iter().filter(|write| write.audio).count() >= MAX_QUEUED_AUDIO_FRAMES {
            return Ok(false);
        }
        let bytes = self.sender.seal_audio(timestamp_ms, opus_packet)?;
        self.writes.push_back(PendingMediaWrite {
            bytes,
            offset: 0,
            audio: true,
            queued_at: Instant::now(),
        });
        Ok(true)
    }

    fn take_audio(&mut self) -> Option<CallAudioFrame> {
        if !self.playout_started {
            if self.jitter.len() < JITTER_START_FRAMES {
                return None;
            }
            self.playout_started = true;
        }
        let frame = self.jitter.pop_front();
        if frame.is_none() {
            self.playout_started = false;
        }
        frame
    }

    fn pump(&mut self, call_id: [u8; 16]) -> std::result::Result<bool, MediaFailure> {
        self.pump_writes()?;
        self.pump_reads(call_id)?;
        Ok(self.hello_written && self.hello_received)
    }

    fn drop_stale_audio(&mut self) {
        self.writes.retain(|write| {
            !write.audio || write.offset != 0 || write.queued_at.elapsed() <= MAX_QUEUED_AUDIO_AGE
        });
    }

    fn pump_writes(&mut self) -> std::result::Result<(), MediaFailure> {
        self.drop_stale_audio();
        let mut context = Context::from_waker(noop_waker_ref());
        for _ in 0..32 {
            let Some(front) = self.writes.front_mut() else {
                break;
            };
            let written = match Pin::new(&mut self.stream)
                .poll_write(&mut context, &front.bytes[front.offset..])
            {
                Poll::Ready(Ok(0)) | Poll::Ready(Err(_)) => return Err(MediaFailure::Link),
                Poll::Ready(Ok(written)) => written,
                Poll::Pending => break,
            };
            front.offset += written;
            if front.offset == front.bytes.len() {
                let completed = self.writes.pop_front().expect("front exists");
                if !completed.audio {
                    self.hello_written = true;
                }
            }
        }
        if self.writes.is_empty()
            && matches!(
                Pin::new(&mut self.stream).poll_flush(&mut context),
                Poll::Ready(Err(_))
            )
        {
            return Err(MediaFailure::Link);
        }
        Ok(())
    }

    fn pump_reads(&mut self, call_id: [u8; 16]) -> std::result::Result<(), MediaFailure> {
        let mut context = Context::from_waker(noop_waker_ref());
        for _ in 0..32 {
            let mut chunk = [0u8; MAX_CALL_MEDIA_FRAME_LEN];
            match Pin::new(&mut self.stream).poll_read(&mut context, &mut chunk) {
                Poll::Ready(Ok(0)) | Poll::Ready(Err(_)) => return Err(MediaFailure::Link),
                Poll::Ready(Ok(read)) => {
                    self.reads.extend_from_slice(&chunk[..read]);
                    if self.reads.len() > MAX_MEDIA_READ_BUFFER {
                        return Err(MediaFailure::Authentication);
                    }
                    self.open_complete_records(call_id)?;
                }
                Poll::Pending => break,
            }
        }
        Ok(())
    }

    fn open_complete_records(
        &mut self,
        call_id: [u8; 16],
    ) -> std::result::Result<(), MediaFailure> {
        loop {
            if self.reads.len() < CALL_MEDIA_HEADER_LEN {
                return Ok(());
            }
            let length = call_media_record_len(&self.reads[..CALL_MEDIA_HEADER_LEN])
                .map_err(|_| MediaFailure::Authentication)?;
            if self.reads.len() < length {
                return Ok(());
            }
            let record = self.reads.drain(..length).collect::<Vec<_>>();
            let mut frame = self
                .receiver
                .open(&record)
                .map_err(|_| MediaFailure::Authentication)?;
            match frame.kind {
                CallMediaKind::Hello => self.hello_received = true,
                CallMediaKind::Audio => {
                    while self.jitter.len() >= JITTER_MAX_FRAMES {
                        self.jitter.pop_front();
                    }
                    let opus_packet = std::mem::take(&mut frame.payload);
                    self.jitter.push_back(CallAudioFrame {
                        call_id,
                        sequence: frame.sequence,
                        timestamp_ms: frame.timestamp_ms,
                        opus_packet,
                    });
                }
            }
        }
    }
}

impl Node {
    /// Return the current honest call-start verdict for one stored contact.
    pub fn call_availability(&self, peer: &[u8; 32], now: u64) -> Result<CallAvailability> {
        self.store
            .get_contact(peer)?
            .ok_or(NodeError::UnknownPeer)?;
        let unavailable = if self.has_live_call() {
            Some(CallUnavailableReason::AlreadyInCall)
        } else {
            match self.carrier_capability(peer, now)?.capability {
                CarrierCapability::OfflineOrUnknown => {
                    Some(CallUnavailableReason::OfflineOrUnknown)
                }
                CarrierCapability::Bulk => Some(CallUnavailableReason::BulkOnly),
                CarrierCapability::MeshOnly => Some(CallUnavailableReason::MeshOnly),
                CarrierCapability::Realtime => {
                    let devices = self.call_devices(peer)?;
                    if devices.is_empty()
                        || devices
                            .iter()
                            .any(|device| !self.sessions.contains_key(device))
                    {
                        Some(CallUnavailableReason::MissingSession)
                    } else if devices.iter().any(|device| {
                        !self
                            .store
                            .get_capabilities(device)
                            .ok()
                            .flatten()
                            .is_some_and(|capabilities| {
                                capabilities.supports(CONTENT_FORMAT_V1, CONTENT_KIND_CALL_CONTROL)
                            })
                    }) {
                        Some(CallUnavailableReason::Unsupported)
                    } else {
                        None
                    }
                }
            }
        };
        Ok(CallAvailability {
            peer: *peer,
            unavailable,
        })
    }

    /// Return every current and briefly retained terminal call, without secrets.
    pub fn calls(&self) -> Vec<CallInfo> {
        let mut calls = self
            .calls
            .values()
            .map(|call| call.info.clone())
            .collect::<Vec<_>>();
        calls.sort_by_key(|call| (call.phase == CallPhase::Ended, call.id));
        calls
    }

    /// Start one capability-gated outgoing audio call.
    pub fn start_call(
        &mut self,
        peer: &[u8; 32],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let availability = self.call_availability(peer, now)?;
        if let Some(reason) = availability.unavailable {
            return Err(match reason {
                CallUnavailableReason::Unsupported => NodeError::CallUnsupported,
                CallUnavailableReason::AlreadyInCall => NodeError::CallBusy,
                CallUnavailableReason::MissingSession => NodeError::NoSession,
                CallUnavailableReason::OfflineOrUnknown
                | CallUnavailableReason::BulkOnly
                | CallUnavailableReason::MeshOnly => NodeError::CallUnavailable,
            });
        }
        self.trim_calls(now)?;
        let devices = self.call_devices(peer)?;
        let call_id = random_nonzero::<16>(rng);
        let master_secret = random_nonzero::<32>(rng);
        let initiator_device = self.call_local_device_id();
        let expires_at = now
            .checked_add(CALL_OFFER_LIFETIME_SECS)
            .ok_or(NodeError::InvalidCall)?;
        let control = CallControl::Offer {
            call_id,
            initiator_device,
            expires_at,
            master_secret,
        };
        self.queue_call_control(peer, &devices, &control, now, rng)?;
        let info = CallInfo {
            id: call_id,
            peer: *peer,
            direction: CallDirection::Outgoing,
            phase: CallPhase::Ringing,
            initiator_device,
            responder_device: None,
            expires_at,
            end_reason: None,
        };
        self.calls.insert(
            call_id,
            ActiveCall {
                info: info.clone(),
                master_secret: Some(Zeroizing::new(master_secret)),
                offered_devices: devices,
                negative_responses: HashSet::new(),
                saw_decline: false,
                updated_at: now,
                media: None,
                media_failures: 0,
                media_lost_at: None,
            },
        );
        self.events.push_back(Event::CallUpdated { call: info });
        Ok(call_id)
    }

    /// Answer one unexpired incoming offer on this exact physical device.
    pub fn answer_call(
        &mut self,
        call_id: &[u8; 16],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let call = self.calls.get(call_id).ok_or(NodeError::UnknownCall)?;
        if call.info.direction != CallDirection::Incoming
            || call.info.phase != CallPhase::Ringing
            || now >= call.info.expires_at
        {
            return Err(NodeError::InvalidCall);
        }
        let peer = call.info.peer;
        let initiator = call.info.initiator_device;
        let expires_at = call.info.expires_at;
        let responder = self.call_local_device_id();
        self.queue_call_control(
            &peer,
            &[initiator],
            &CallControl::Answer {
                call_id: *call_id,
                initiator_device: initiator,
                responder_device: responder,
                expires_at,
            },
            now,
            rng,
        )?;
        let call = self.calls.get_mut(call_id).expect("checked above");
        call.info.phase = CallPhase::Connecting;
        call.info.responder_device = Some(responder);
        call.updated_at = now;
        self.events.push_back(Event::CallUpdated {
            call: call.info.clone(),
        });
        Ok(())
    }

    /// Decline one unexpired incoming offer.
    pub fn decline_call(
        &mut self,
        call_id: &[u8; 16],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let call = self.calls.get(call_id).ok_or(NodeError::UnknownCall)?;
        if call.info.direction != CallDirection::Incoming
            || call.info.phase != CallPhase::Ringing
            || now >= call.info.expires_at
        {
            return Err(NodeError::InvalidCall);
        }
        let peer = call.info.peer;
        let initiator = call.info.initiator_device;
        let expires_at = call.info.expires_at;
        self.queue_call_control(
            &peer,
            &[initiator],
            &CallControl::Decline {
                call_id: *call_id,
                initiator_device: initiator,
                responder_device: self.call_local_device_id(),
                expires_at,
            },
            now,
            rng,
        )?;
        self.end_call(call_id, CallEndReason::Declined, now)
    }

    /// Cancel one outgoing offer before an answer wins.
    pub fn cancel_call(
        &mut self,
        call_id: &[u8; 16],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let call = self.calls.get(call_id).ok_or(NodeError::UnknownCall)?;
        if call.info.direction != CallDirection::Outgoing || call.info.phase != CallPhase::Ringing {
            return Err(NodeError::InvalidCall);
        }
        let peer = call.info.peer;
        let initiator = call.info.initiator_device;
        let expires_at = call.info.expires_at;
        let devices = call.offered_devices.clone();
        self.queue_call_control(
            &peer,
            &devices,
            &CallControl::Cancel {
                call_id: *call_id,
                initiator_device: initiator,
                expires_at,
            },
            now,
            rng,
        )?;
        self.end_call(call_id, CallEndReason::Cancelled, now)
    }

    /// End an answered or active call from either local role.
    pub fn hangup_call(
        &mut self,
        call_id: &[u8; 16],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let call = self.calls.get(call_id).ok_or(NodeError::UnknownCall)?;
        if !matches!(call.info.phase, CallPhase::Connecting | CallPhase::Active) {
            return Err(NodeError::InvalidCall);
        }
        let responder = call.info.responder_device.ok_or(NodeError::InvalidCall)?;
        let peer = call.info.peer;
        let target = match call.info.direction {
            CallDirection::Outgoing => responder,
            CallDirection::Incoming => call.info.initiator_device,
        };
        let control = CallControl::Hangup {
            call_id: *call_id,
            initiator_device: call.info.initiator_device,
            responder_device: responder,
            expires_at: call.info.expires_at,
            reason: CallHangupReason::Ended,
        };
        self.queue_call_control(&peer, &[target], &control, now, rng)?;
        self.end_call(call_id, CallEndReason::HungUp, now)
    }

    /// Mark media active only after the stream layer verified both hello records.
    pub fn mark_call_active(&mut self, call_id: &[u8; 16], now: u64) -> Result<()> {
        let call = self.calls.get_mut(call_id).ok_or(NodeError::UnknownCall)?;
        if call.info.phase != CallPhase::Connecting || call.info.responder_device.is_none() {
            return Err(NodeError::InvalidCall);
        }
        call.info.phase = CallPhase::Active;
        call.updated_at = now;
        self.events.push_back(Event::CallUpdated {
            call: call.info.clone(),
        });
        Ok(())
    }

    /// Advance direct-QUIC stream establishment, proof-of-key hellos, bounded
    /// writes, decryption, and jitter buffering without blocking the ordinary
    /// message heartbeat. Shell runtimes call this on their media cadence.
    pub async fn pump_call_media(&mut self, now: u64) -> Result<()> {
        self.accept_incoming_call_streams()?;

        let outgoing = self
            .calls
            .iter()
            .filter(|(_, call)| {
                call.info.direction == CallDirection::Outgoing
                    && call.info.phase == CallPhase::Connecting
                    && call.media.is_none()
            })
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for call_id in outgoing {
            self.open_outgoing_call_stream(call_id, now).await?;
        }

        let mut activated = Vec::new();
        let mut retry = Vec::new();
        let mut ended = Vec::new();
        let mut active_media_lost = Vec::new();
        for (call_id, call) in &mut self.calls {
            let Some(media) = &mut call.media else {
                continue;
            };
            match media.pump(*call_id) {
                Ok(ready) if ready && call.info.phase == CallPhase::Connecting => {
                    call.info.phase = CallPhase::Active;
                    call.master_secret.take();
                    call.updated_at = now;
                    activated.push(call.info.clone());
                }
                Ok(_) => {}
                Err(failure)
                    if call.info.direction == CallDirection::Incoming
                        && call.info.phase == CallPhase::Connecting
                        && call.media_failures < MAX_MEDIA_HANDSHAKE_FAILURES =>
                {
                    call.media_failures = call.media_failures.saturating_add(1);
                    retry.push((*call_id, failure));
                }
                Err(_) if call.info.phase == CallPhase::Active => active_media_lost.push(*call_id),
                Err(_) => ended.push(*call_id),
            }
        }
        for (call_id, _) in retry {
            if let Some(call) = self.calls.get_mut(&call_id) {
                call.media.take();
            }
        }
        for call_id in active_media_lost {
            if let Some(call) = self.calls.get_mut(&call_id) {
                call.media.take();
                call.media_lost_at = Some(now);
                call.updated_at = now;
            }
        }
        for call in activated {
            self.events.push_back(Event::CallUpdated { call });
        }
        for call_id in ended {
            self.end_call(&call_id, CallEndReason::RouteLost, now)?;
        }
        Ok(())
    }

    /// Seal and queue one native-encoded Opus packet for an active call.
    /// Returns `false` when the bounded writer is full; callers should drop
    /// that capture packet rather than build latency.
    pub fn send_call_audio(
        &mut self,
        call_id: &[u8; 16],
        timestamp_ms: u64,
        opus_packet: &[u8],
    ) -> Result<bool> {
        let call = self.calls.get_mut(call_id).ok_or(NodeError::UnknownCall)?;
        if call.info.phase != CallPhase::Active {
            return Err(NodeError::InvalidCall);
        }
        call.media
            .as_mut()
            .ok_or(NodeError::InvalidCall)?
            .queue_audio(timestamp_ms, opus_packet)
    }

    /// Release at most one authenticated Opus packet according to the core's
    /// bounded jitter policy. `None` means playout should wait or underrun;
    /// packets are never synthesized, repeated, or returned before both media
    /// hellos authenticated.
    pub fn take_call_audio(&mut self, call_id: &[u8; 16]) -> Result<Option<CallAudioFrame>> {
        let call = self.calls.get_mut(call_id).ok_or(NodeError::UnknownCall)?;
        if call.info.phase != CallPhase::Active {
            return Err(NodeError::InvalidCall);
        }
        Ok(call
            .media
            .as_mut()
            .ok_or(NodeError::InvalidCall)?
            .take_audio())
    }

    fn accept_incoming_call_streams(&mut self) -> Result<()> {
        let transports = self.transports.clone();
        let mut admitted = 0usize;
        for transport in transports {
            while admitted < 16 {
                let Some(stream) = transport.try_accept_call_stream()? else {
                    break;
                };
                admitted += 1;
                let candidate = self
                    .calls
                    .iter()
                    .find(|(_, call)| {
                        call.info.direction == CallDirection::Incoming
                            && call.info.phase == CallPhase::Connecting
                            && call.media.is_none()
                    })
                    .map(|(id, _)| *id);
                if let Some(call_id) = candidate {
                    self.install_call_stream(call_id, stream)?;
                }
                // Without one exact connecting inbound call, dropping the
                // unauthenticated stream is the complete response.
            }
        }
        Ok(())
    }

    async fn open_outgoing_call_stream(&mut self, call_id: [u8; 16], now: u64) -> Result<()> {
        let responder = self
            .calls
            .get(&call_id)
            .and_then(|call| call.info.responder_device)
            .ok_or(NodeError::InvalidCall)?;
        let hints = self.hints_for(&responder)?;
        let transports = self.transports.clone();
        for transport in transports {
            for hint in &hints {
                if !transport.call_ready(hint) {
                    continue;
                }
                if let Ok(stream) = transport.open_call_stream(hint).await {
                    return self.install_call_stream(call_id, stream);
                }
            }
        }
        self.end_call(&call_id, CallEndReason::RouteLost, now)
    }

    fn install_call_stream(&mut self, call_id: [u8; 16], stream: CallStream) -> Result<()> {
        let local_account = self.peer_id();
        let call = self.calls.get_mut(&call_id).ok_or(NodeError::UnknownCall)?;
        if call.info.phase != CallPhase::Connecting || call.media.is_some() {
            return Err(NodeError::InvalidCall);
        }
        let secret = call
            .master_secret
            .as_deref()
            .ok_or(NodeError::InvalidCall)?;
        let context = call_media_context(local_account, &call.info)?;
        let role = match call.info.direction {
            CallDirection::Outgoing => CallRole::Initiator,
            CallDirection::Incoming => CallRole::Responder,
        };
        call.media = Some(CallMediaState::new(stream, secret, &context, role)?);
        Ok(())
    }

    pub(crate) fn apply_call_control(
        &mut self,
        peer: [u8; 32],
        peer_device: [u8; 32],
        control: CallControl,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        if self.account_for_device(&peer_device)? != peer {
            return Err(NodeError::InvalidCall);
        }
        match control {
            CallControl::Offer {
                call_id,
                initiator_device,
                expires_at,
                master_secret,
            } => {
                if initiator_device != peer_device
                    || expires_at <= now
                    || expires_at > now.saturating_add(MAX_CALL_OFFER_LIFETIME_SECS)
                {
                    return Err(NodeError::InvalidCall);
                }
                if self.calls.contains_key(&call_id) {
                    return Ok(());
                }
                if self.has_live_call() {
                    let _ = self.queue_call_control(
                        &peer,
                        &[initiator_device],
                        &CallControl::Busy {
                            call_id,
                            initiator_device,
                            responder_device: self.call_local_device_id(),
                            expires_at,
                        },
                        now,
                        rng,
                    );
                    return Ok(());
                }
                self.trim_calls(now)?;
                let info = CallInfo {
                    id: call_id,
                    peer,
                    direction: CallDirection::Incoming,
                    phase: CallPhase::Ringing,
                    initiator_device,
                    responder_device: None,
                    expires_at,
                    end_reason: None,
                };
                self.calls.insert(
                    call_id,
                    ActiveCall {
                        info: info.clone(),
                        master_secret: Some(Zeroizing::new(master_secret)),
                        offered_devices: vec![self.call_local_device_id()],
                        negative_responses: HashSet::new(),
                        saw_decline: false,
                        updated_at: now,
                        media: None,
                        media_failures: 0,
                        media_lost_at: None,
                    },
                );
                self.events.push_back(Event::CallUpdated { call: info });
            }
            CallControl::Answer {
                call_id,
                initiator_device,
                responder_device,
                expires_at,
            } => {
                if responder_device != peer_device {
                    return Err(NodeError::InvalidCall);
                }
                let Some(call) = self.calls.get(&call_id) else {
                    return Ok(());
                };
                if !matching_outgoing(call, peer, initiator_device, expires_at) {
                    return Err(NodeError::InvalidCall);
                }
                if call.info.phase == CallPhase::Ringing && now < expires_at {
                    let losers = call
                        .offered_devices
                        .iter()
                        .copied()
                        .filter(|device| *device != responder_device)
                        .collect::<Vec<_>>();
                    let call = self.calls.get_mut(&call_id).expect("checked above");
                    call.info.phase = CallPhase::Connecting;
                    call.info.responder_device = Some(responder_device);
                    call.updated_at = now;
                    let info = call.info.clone();
                    self.events.push_back(Event::CallUpdated { call: info });
                    for loser in losers {
                        let _ = self.queue_call_control(
                            &peer,
                            &[loser],
                            &CallControl::Hangup {
                                call_id,
                                initiator_device,
                                responder_device: loser,
                                expires_at,
                                reason: CallHangupReason::AnsweredElsewhere,
                            },
                            now,
                            rng,
                        );
                    }
                } else if call.info.responder_device != Some(responder_device) {
                    let _ = self.queue_call_control(
                        &peer,
                        &[responder_device],
                        &CallControl::Hangup {
                            call_id,
                            initiator_device,
                            responder_device,
                            expires_at,
                            reason: CallHangupReason::AnsweredElsewhere,
                        },
                        now,
                        rng,
                    );
                }
            }
            CallControl::Decline {
                call_id,
                initiator_device,
                responder_device,
                expires_at,
            }
            | CallControl::Busy {
                call_id,
                initiator_device,
                responder_device,
                expires_at,
            } => {
                if responder_device != peer_device {
                    return Err(NodeError::InvalidCall);
                }
                let is_decline = matches!(control, CallControl::Decline { .. });
                let Some(call) = self.calls.get_mut(&call_id) else {
                    return Ok(());
                };
                if !matching_outgoing(call, peer, initiator_device, expires_at) {
                    return Err(NodeError::InvalidCall);
                }
                if call.info.phase != CallPhase::Ringing {
                    return Ok(());
                }
                call.negative_responses.insert(responder_device);
                call.saw_decline |= is_decline;
                if call.negative_responses.len() >= call.offered_devices.len() {
                    let reason = if call.saw_decline {
                        CallEndReason::Declined
                    } else {
                        CallEndReason::Busy
                    };
                    self.end_call(&call_id, reason, now)?;
                }
            }
            CallControl::Cancel {
                call_id,
                initiator_device,
                expires_at,
            } => {
                if initiator_device != peer_device {
                    return Err(NodeError::InvalidCall);
                }
                let Some(call) = self.calls.get(&call_id) else {
                    return Ok(());
                };
                if !matching_incoming(call, peer, initiator_device, expires_at) {
                    return Err(NodeError::InvalidCall);
                }
                if call.info.phase != CallPhase::Ended {
                    self.end_call(&call_id, CallEndReason::Cancelled, now)?;
                }
            }
            CallControl::Hangup {
                call_id,
                initiator_device,
                responder_device,
                expires_at,
                reason,
            } => {
                let Some(call) = self.calls.get(&call_id) else {
                    return Ok(());
                };
                let valid = match call.info.direction {
                    CallDirection::Outgoing => {
                        matching_outgoing(call, peer, initiator_device, expires_at)
                            && responder_device == peer_device
                            && call.info.responder_device == Some(responder_device)
                            && reason == CallHangupReason::Ended
                    }
                    CallDirection::Incoming => {
                        matching_incoming(call, peer, initiator_device, expires_at)
                            && initiator_device == peer_device
                            && responder_device == self.call_local_device_id()
                    }
                };
                if !valid {
                    return Err(NodeError::InvalidCall);
                }
                if call.info.phase != CallPhase::Ended {
                    let end_reason = match reason {
                        CallHangupReason::Ended => CallEndReason::HungUp,
                        CallHangupReason::AnsweredElsewhere => CallEndReason::AnsweredElsewhere,
                    };
                    self.end_call(&call_id, end_reason, now)?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn sweep_calls(&mut self, now: u64) -> Result<()> {
        let expired = self
            .calls
            .iter()
            .filter(|(_, call)| {
                call.info.phase == CallPhase::Ringing && now >= call.info.expires_at
            })
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for id in expired {
            self.end_call(&id, CallEndReason::Expired, now)?;
        }
        let route_lost = self
            .calls
            .iter()
            .filter(|(_, call)| {
                call.info.phase == CallPhase::Active
                    && call.media_lost_at.is_some_and(|lost_at| {
                        now.saturating_sub(lost_at) >= MEDIA_ROUTE_LOSS_GRACE_SECS
                    })
            })
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for id in route_lost {
            self.end_call(&id, CallEndReason::RouteLost, now)?;
        }
        let expired_queue = self
            .call_queue_deadlines
            .iter()
            .filter(|(_, deadline)| now >= **deadline)
            .map(|(seq, _)| *seq)
            .collect::<Vec<_>>();
        for seq in expired_queue {
            self.store.queue_ack(seq)?;
            self.call_queue_deadlines.remove(&seq);
            self.backoff.remove(&seq);
        }
        self.trim_calls(now)
    }

    fn queue_call_control(
        &mut self,
        peer: &[u8; 32],
        devices: &[[u8; 32]],
        control: &CallControl,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        if devices.is_empty() {
            return Err(NodeError::NoSession);
        }
        let event_id = random_nonzero::<16>(rng);
        let wire = encode_call_control(event_id, control)?;
        let padded = pad(&wire)?;
        let deadline = match control {
            CallControl::Hangup { .. } => now.saturating_add(30),
            _ => control.expires_at(),
        };
        if deadline <= now {
            return Err(NodeError::InvalidCall);
        }
        for device in devices {
            if self.account_for_device(device)? != *peer {
                return Err(NodeError::InvalidCall);
            }
            let session = self.sessions.get_mut(device).ok_or(NodeError::NoSession)?;
            let message = session.encrypt(rng, now, &padded, &[]);
            let token = delivery_token(
                &MailboxKey::from_bytes(*session.mailbox_key()),
                epoch_day(now),
                device,
            );
            self.store.put_session(device, session, rng)?;
            let seq = self.store.queue_push(
                &QueueItem {
                    peer: *device,
                    msg_id: None,
                    group_msg_id: None,
                    class: QueueClass::Realtime,
                    envelope: Envelope::new(EnvelopeKind::Message, token, message.encode()),
                },
                rng,
            )?;
            self.call_queue_deadlines.insert(seq, deadline);
        }
        Ok(())
    }

    fn call_devices(&self, peer: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
        let mut devices = self
            .store
            .contact_devices_for(peer)?
            .into_iter()
            .filter(|endpoint| endpoint.revoked_at.is_none())
            .map(|endpoint| endpoint.device)
            .collect::<Vec<_>>();
        if devices.is_empty() && self.store.get_contact(peer)?.is_some() {
            devices.push(*peer);
        }
        devices.sort_unstable();
        devices.dedup();
        Ok(devices)
    }

    /// Single-device wire compatibility authenticates the stable account key
    /// as its sole endpoint. Once C2 is active, every ratchet endpoint is the
    /// separately certified physical-device key instead.
    fn call_local_device_id(&self) -> [u8; 32] {
        if self.linked_devices().len() > 1 {
            self.device_id()
        } else {
            self.peer_id()
        }
    }

    fn has_live_call(&self) -> bool {
        self.calls
            .values()
            .any(|call| call.info.phase != CallPhase::Ended)
    }

    fn end_call(&mut self, call_id: &[u8; 16], reason: CallEndReason, now: u64) -> Result<()> {
        let call = self.calls.get_mut(call_id).ok_or(NodeError::UnknownCall)?;
        if call.info.phase == CallPhase::Ended {
            return Ok(());
        }
        call.media.take();
        call.master_secret.take();
        call.info.phase = CallPhase::Ended;
        call.info.end_reason = Some(reason);
        call.updated_at = now;
        self.events.push_back(Event::CallUpdated {
            call: call.info.clone(),
        });
        Ok(())
    }

    fn trim_calls(&mut self, now: u64) -> Result<()> {
        self.calls.retain(|_, call| {
            call.info.phase != CallPhase::Ended
                || now.saturating_sub(call.updated_at) <= TERMINAL_CALL_RETENTION_SECS
        });
        while self.calls.len() >= MAX_TRANSIENT_CALLS {
            let Some(oldest) = self
                .calls
                .iter()
                .filter(|(_, call)| call.info.phase == CallPhase::Ended)
                .min_by_key(|(_, call)| call.updated_at)
                .map(|(id, _)| *id)
            else {
                return Err(NodeError::CallBusy);
            };
            self.calls.remove(&oldest);
        }
        Ok(())
    }
}

fn call_media_context(local_account: [u8; 32], info: &CallInfo) -> Result<CallMediaContext> {
    let responder_device = info.responder_device.ok_or(NodeError::InvalidCall)?;
    let (initiator_account, responder_account) = match info.direction {
        CallDirection::Outgoing => (local_account, info.peer),
        CallDirection::Incoming => (info.peer, local_account),
    };
    Ok(CallMediaContext {
        call_id: info.id,
        initiator_account,
        responder_account,
        initiator_device: info.initiator_device,
        responder_device,
    })
}

fn matching_outgoing(
    call: &ActiveCall,
    peer: [u8; 32],
    initiator: [u8; 32],
    expires_at: u64,
) -> bool {
    call.info.direction == CallDirection::Outgoing
        && call.info.peer == peer
        && call.info.initiator_device == initiator
        && call.info.expires_at == expires_at
}

fn matching_incoming(
    call: &ActiveCall,
    peer: [u8; 32],
    initiator: [u8; 32],
    expires_at: u64,
) -> bool {
    call.info.direction == CallDirection::Incoming
        && call.info.peer == peer
        && call.info.initiator_device == initiator
        && call.info.expires_at == expires_at
}

fn random_nonzero<const N: usize>(rng: &mut impl CryptoRngCore) -> [u8; N] {
    loop {
        let mut bytes = [0u8; N];
        rng.fill_bytes(&mut bytes);
        if bytes.iter().any(|byte| *byte != 0) {
            return bytes;
        }
    }
}
