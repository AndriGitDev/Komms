//! Transient account-aware call signaling (ADR-0013).

use std::collections::HashSet;

use rand_core::CryptoRngCore;
use zeroize::Zeroizing;

use kult_protocol::{encode_call_control, pad, CallControl, Envelope, EnvelopeKind, MailboxKey};
use kult_store::{QueueClass, QueueItem};

use crate::{
    delivery_token, epoch_day, CallAvailability, CallDirection, CallEndReason, CallInfo, CallPhase,
    CallUnavailableReason, CarrierCapability, Event, Node, NodeError, Result, CONTENT_FORMAT_V1,
    CONTENT_KIND_CALL_CONTROL,
};

/// Offers are short-lived and never become delayed-message work.
pub const CALL_OFFER_LIFETIME_SECS: u64 = 60;
/// Reject remote offers that claim an unexpectedly distant deadline.
pub const MAX_CALL_OFFER_LIFETIME_SECS: u64 = 90;
/// Keep terminal render state briefly, while retaining no secret bytes.
const TERMINAL_CALL_RETENTION_SECS: u64 = 300;
/// Bound all transient call state, including recently ended rows.
const MAX_TRANSIENT_CALLS: usize = 32;

pub(crate) struct ActiveCall {
    info: CallInfo,
    master_secret: Option<Zeroizing<[u8; 32]>>,
    offered_devices: Vec<[u8; 32]>,
    negative_responses: HashSet<[u8; 32]>,
    saw_decline: bool,
    updated_at: u64,
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
            } => {
                let Some(call) = self.calls.get(&call_id) else {
                    return Ok(());
                };
                let valid = match call.info.direction {
                    CallDirection::Outgoing => {
                        matching_outgoing(call, peer, initiator_device, expires_at)
                            && responder_device == peer_device
                            && call.info.responder_device == Some(responder_device)
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
                    let reason = if call.info.phase == CallPhase::Ringing {
                        CallEndReason::AnsweredElsewhere
                    } else {
                        CallEndReason::HungUp
                    };
                    self.end_call(&call_id, reason, now)?;
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
