//! KommsKult runtime (docs/03-architecture.md §2): composes the crypto core,
//! protocol layer, encrypted store and transports into one event-driven node.
//!
//! Responsibilities, and nothing else:
//!
//! - **Session lifecycle** — initiating handshakes from stored prekey
//!   bundles, answering inbound handshakes from the local prekey vault,
//!   persisting ratchet state after every step.
//! - **Delivery engine** — every outbound message is persisted `Queued`
//!   before any crypto runs, advances to `Sent` only when a transport
//!   actually accepted the envelope, and to `Delivered` only on an
//!   end-to-end encrypted receipt. Nothing is ever faked.
//! - **Transport scheduler** — ranks the registered carriers per recipient
//!   by (reachability, latency class, cost class) and falls through the
//!   ranking on failure; failed items retry with exponential backoff.
//! - **Dedup & reassembly** — inbound envelopes are deduplicated by content
//!   id (multipath duplicates are normal), fragments reassembled, and
//!   envelopes that arrive before the session that can read them (courier
//!   reordering) are stashed persistently and retried — never lost, never
//!   double-processed.
//!
//! Driving the node: applications call commands ([`Node::send_message`],
//! [`Node::add_contact`], … or the [`Command`] enum) and then pump
//! [`Node::tick`] — one receive/flush cycle — collecting [`Event`]s.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;

use kult_crypto::{
    initiate, open_anonymous, respond, safety_number, seal_anonymous, Identity, IdentityPublic,
    InitialMessage, KdfProfile, PrekeyBundle, RatchetMessage, SafetyNumber,
};
use kult_protocol::{
    delivery_token, epoch_day, fragment, intro_token, pad, unpad, Envelope, EnvelopeKind,
    MailboxKey, Reassembler, ReceiptPayload, ENVELOPE_HEADER_LEN,
};
use kult_store::{ContactRecord, DeliveryState, Direction, MessageRecord, QueueItem, Store};
use kult_transport::{DeliveryHint, Reachability, Transport};

mod api;
mod error;
mod vault;

pub use api::{Command, Event};
pub use error::NodeError;

use vault::PrekeyVault;

/// Convenience alias.
pub type Result<T> = std::result::Result<T, NodeError>;

/// Associated data for anonymous-boxed handshake flights (fixed across the
/// protocol; also used by the M2 acceptance tests).
const HS_AD: &[u8] = b"KK-handshake-v1";

/// Prekey bundles expire after 30 days (docs/06-identity-trust.md).
const BUNDLE_TTL_SECS: u64 = 30 * 86_400;

/// How many past daily epochs of delivery tokens the receiver recognizes.
/// Sneakernet latency is human-scale; a courier bundle a month old must
/// still route (docs/05-transports.md §5).
const TOKEN_LOOKBACK_EPOCHS: u64 = 35;
/// Future epochs tolerated (sender clock ahead of ours).
const TOKEN_LOOKAHEAD_EPOCHS: u64 = 2;

/// Retention for inbound envelopes that cannot be consumed yet (arrived
/// before their session). Matches the bundle TTL: after a month the
/// handshake that would unlock them can no longer arrive either.
const PENDING_TTL_SECS: u64 = 30 * 86_400;

/// Retry backoff: base delay, doubling per attempt, capped.
const RETRY_BASE_SECS: u64 = 30;
const RETRY_CAP_SECS: u64 = 3_600;

struct Backoff {
    attempts: u32,
    next_ok: u64,
}

enum Consumed {
    /// Fully handled (or permanently unprocessable) — never seen again.
    Done,
    /// Cannot be processed *yet* (no matching session) — stash and retry.
    Later,
}

/// The KommsKult runtime: one identity, one store, any number of transports.
pub struct Node {
    store: Store,
    identity: Identity,
    vault: PrekeyVault,
    transports: Vec<Arc<dyn Transport>>,
    sessions: HashMap<[u8; 32], kult_crypto::Session>,
    reassembler: Reassembler,
    backoff: HashMap<i64, Backoff>,
    events: VecDeque<Event>,
}

impl Node {
    // ---- lifecycle ---------------------------------------------------------

    /// Create a brand-new node: fresh store, fresh identity, fresh prekeys.
    pub fn create(
        path: &std::path::Path,
        passphrase: &[u8],
        profile: KdfProfile,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let store = Store::create(path, passphrase, profile, rng)?;
        let identity = Identity::generate(rng);
        store.put_identity(&identity, rng)?;
        let vault = PrekeyVault::generate(rng);
        store.put_prekeys(&vault.encode(), rng)?;
        Self::assemble(store, identity, vault)
    }

    /// Open an existing node.
    pub fn open(path: &std::path::Path, passphrase: &[u8]) -> Result<Self> {
        let store = Store::open(path, passphrase)?;
        let identity = store.get_identity()?.ok_or(NodeError::CorruptState)?;
        let vault_blob = store.get_prekeys()?.ok_or(NodeError::CorruptState)?;
        let vault = PrekeyVault::decode(&vault_blob)?;
        Self::assemble(store, identity, vault)
    }

    fn assemble(store: Store, identity: Identity, vault: PrekeyVault) -> Result<Self> {
        let mut sessions = HashMap::new();
        for contact in store.contacts()? {
            if let Some(s) = store.get_session(&contact.peer)? {
                sessions.insert(contact.peer, s);
            }
        }
        Ok(Self {
            store,
            identity,
            vault,
            transports: Vec::new(),
            sessions,
            reassembler: Reassembler::new(),
            backoff: HashMap::new(),
            events: VecDeque::new(),
        })
    }

    /// Register a transport. Order does not matter — the scheduler ranks by
    /// link profile per delivery, not registration order.
    pub fn add_transport(&mut self, transport: Arc<dyn Transport>) {
        self.transports.push(transport);
    }

    // ---- identity ----------------------------------------------------------

    /// This node's peer id (Ed25519 identity key bytes) — what contacts key
    /// conversations by.
    pub fn peer_id(&self) -> [u8; 32] {
        self.identity.public().ed
    }

    /// This node's public identity.
    pub fn public(&self) -> IdentityPublic {
        self.identity.public()
    }

    /// This node's human-shareable kult address.
    pub fn address(&self) -> String {
        self.identity.public().address()
    }

    /// The safety number for out-of-band verification with a contact
    /// (docs/04-cryptography.md §9).
    pub fn safety_number_with(&self, peer: &[u8; 32]) -> Result<SafetyNumber> {
        let contact = self
            .store
            .get_contact(peer)?
            .ok_or(NodeError::UnknownPeer)?;
        let their: IdentityPublic =
            postcard::from_bytes(&contact.identity).map_err(|_| NodeError::CorruptState)?;
        Ok(safety_number(&self.identity.public(), &their))
    }

    /// Export a fresh signed prekey bundle for out-of-band sharing (QR, file,
    /// dictation). Each call mints a new one-time prekey, so hand each
    /// prospective contact their own bundle.
    pub fn handshake_bundle(&mut self, now: u64, rng: &mut impl CryptoRngCore) -> Result<Vec<u8>> {
        let opk = self.vault.fresh_opk(rng);
        self.store.put_prekeys(&self.vault.encode(), rng)?;
        let bundle = PrekeyBundle::build(
            &self.identity,
            &self.vault.spk(),
            &self.vault.pqspk()?,
            Some(&opk),
            now + BUNDLE_TTL_SECS,
            vec![],
        );
        Ok(bundle.encode())
    }

    // ---- contacts ----------------------------------------------------------

    /// Add (or replace) a contact from their encoded prekey bundle. The
    /// bundle is signature-verified before anything is stored. Returns the
    /// contact's peer id.
    pub fn add_contact(
        &mut self,
        name: &str,
        bundle_bytes: &[u8],
        hints: &[DeliveryHint],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 32]> {
        let verified = PrekeyBundle::decode(bundle_bytes)?.verify(now)?;
        let peer = verified.bundle().identity.ed;
        let identity = postcard::to_allocvec(&verified.bundle().identity)
            .map_err(|_| NodeError::CorruptState)?;
        self.store.put_contact(
            &ContactRecord {
                peer,
                identity,
                name: name.to_owned(),
                bundle: bundle_bytes.to_vec(),
                hints: encode_hints(hints),
                verified: false,
            },
            rng,
        )?;
        Ok(peer)
    }

    /// Replace a contact's delivery hints.
    pub fn set_hints(
        &mut self,
        peer: &[u8; 32],
        hints: &[DeliveryHint],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let mut contact = self
            .store
            .get_contact(peer)?
            .ok_or(NodeError::UnknownPeer)?;
        contact.hints = encode_hints(hints);
        self.store.put_contact(&contact, rng)?;
        Ok(())
    }

    /// Record that safety numbers were verified out-of-band.
    pub fn mark_verified(&mut self, peer: &[u8; 32], rng: &mut impl CryptoRngCore) -> Result<()> {
        let mut contact = self
            .store
            .get_contact(peer)?
            .ok_or(NodeError::UnknownPeer)?;
        contact.verified = true;
        self.store.put_contact(&contact, rng)?;
        Ok(())
    }

    /// All stored contacts.
    pub fn contacts(&self) -> Result<Vec<ContactRecord>> {
        Ok(self.store.contacts()?)
    }

    /// Message history with a peer, in insertion order.
    pub fn messages_with(&self, peer: &[u8; 32]) -> Result<Vec<MessageRecord>> {
        Ok(self.store.messages_with(peer)?)
    }

    /// Number of envelopes waiting in the outbound queue.
    pub fn queued(&self) -> Result<usize> {
        Ok(self.store.queue_all()?.len())
    }

    // ---- commands ----------------------------------------------------------

    /// Execute one [`Command`] — the single serializable entry point the FFI
    /// layer wraps. Effects surface as [`Event`]s on the next [`Node::tick`].
    pub fn execute(&mut self, cmd: Command, now: u64, rng: &mut impl CryptoRngCore) -> Result<()> {
        match cmd {
            Command::Send { peer, body } => {
                self.send_message(&peer, &body, now, rng)?;
            }
            Command::AddContact {
                name,
                bundle,
                hints,
            } => {
                self.add_contact(&name, &bundle, &hints, now, rng)?;
            }
            Command::SetHints { peer, hints } => self.set_hints(&peer, &hints, rng)?,
            Command::MarkVerified { peer } => self.mark_verified(&peer, rng)?,
        }
        Ok(())
    }

    /// Queue a message to a contact. Persists the record as `Queued` before
    /// any crypto runs (nothing is lost on crash), establishes the session
    /// from the stored prekey bundle if this is the first message, and
    /// enqueues the sealed envelope for the next flush. Returns the message
    /// record id.
    pub fn send_message(
        &mut self,
        peer: &[u8; 32],
        body: &[u8],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let contact = self
            .store
            .get_contact(peer)?
            .ok_or(NodeError::UnknownPeer)?;

        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        let mut record = MessageRecord {
            id,
            peer: *peer,
            direction: Direction::Outbound,
            state: DeliveryState::Queued,
            timestamp: now,
            body: body.to_vec(),
            wire_id: None,
        };
        self.store.put_message(&record, rng)?;
        self.events.push_back(Event::DeliveryUpdated {
            id,
            state: DeliveryState::Queued,
        });

        let padded = pad(body)?;
        let envelope = if let Some(session) = self.sessions.get_mut(peer) {
            let msg = session.encrypt(rng, now, &padded, &[]);
            let token = delivery_token(
                &MailboxKey::from_bytes(*session.mailbox_key()),
                epoch_day(now),
            );
            self.store.put_session(peer, session, rng)?;
            Envelope::new(EnvelopeKind::Message, token, msg.encode())
        } else {
            if contact.bundle.is_empty() {
                return Err(NodeError::NoSession);
            }
            let bundle = PrekeyBundle::decode(&contact.bundle)?.verify(now)?;
            let (session, init) = initiate(&self.identity, &bundle, &padded, now, rng)?;
            let sealed = seal_anonymous(&bundle.bundle().identity, HS_AD, &init.encode(), rng);
            self.store.put_session(peer, &session, rng)?;
            self.sessions.insert(*peer, session);
            Envelope::new(
                EnvelopeKind::Handshake,
                intro_token(peer, epoch_day(now)),
                sealed,
            )
        };

        record.wire_id = Some(envelope.content_id());
        self.store.update_message(&record, rng)?;
        self.store.queue_push(
            &QueueItem {
                peer: *peer,
                msg_id: Some(id),
                envelope,
            },
            rng,
        )?;
        Ok(id)
    }

    /// Events emitted since the last drain (also returned by [`Node::tick`]).
    pub fn drain_events(&mut self) -> Vec<Event> {
        self.events.drain(..).collect()
    }

    // ---- the heartbeat -----------------------------------------------------

    /// One receive/flush cycle: drain every transport, consume what can be
    /// consumed (dedup → reassemble → decrypt → persist), queue encrypted
    /// receipts for consumed messages, then flush the outbound queue through
    /// the transport scheduler. Returns all events produced.
    pub async fn tick(&mut self, now: u64, rng: &mut impl CryptoRngCore) -> Result<Vec<Event>> {
        // 1. Gather: previously-stashed envelopes first, then fresh arrivals.
        let mut work: Vec<(Envelope, u64)> = self.store.pending_drain()?;
        let transports = self.transports.clone();
        for transport in &transports {
            // A dead link must not stall the others; its envelopes will
            // arrive via retry or another path.
            if let Ok(envelopes) = transport.recv().await {
                work.extend(envelopes.into_iter().map(|e| (e, now)));
            }
        }

        // 2. Consume, re-running over the stash whenever a new session was
        //    established (a handshake later in the batch can unlock messages
        //    earlier in it). Each pass consumes at least one envelope, so
        //    this terminates.
        let mut acks: Vec<([u8; 32], [u8; 16])> = Vec::new();
        loop {
            let mut stash = Vec::new();
            let mut established = false;
            for (env, first_seen) in work {
                match self.consume(&env, 0, now, rng, &mut acks, &mut established)? {
                    Consumed::Done => {}
                    Consumed::Later => stash.push((env, first_seen)),
                }
            }
            if established && !stash.is_empty() {
                work = stash;
                continue;
            }
            for (env, first_seen) in stash {
                if now.saturating_sub(first_seen) <= PENDING_TTL_SECS {
                    self.store.pending_push(&env, first_seen, rng)?;
                }
            }
            break;
        }

        // 3. Acknowledge consumed messages with end-to-end encrypted
        //    receipts, batched per peer.
        let mut acks_by_peer: BTreeMap<[u8; 32], Vec<[u8; 16]>> = BTreeMap::new();
        for (peer, content_id) in acks {
            acks_by_peer.entry(peer).or_default().push(content_id);
        }
        for (peer, content_ids) in acks_by_peer {
            self.queue_receipt(&peer, content_ids, now, rng)?;
        }

        // 4. Flush the outbound queue.
        self.flush(now, rng).await?;

        Ok(self.drain_events())
    }

    // ---- receive path ------------------------------------------------------

    fn consume(
        &mut self,
        env: &Envelope,
        depth: u8,
        now: u64,
        rng: &mut impl CryptoRngCore,
        acks: &mut Vec<([u8; 32], [u8; 16])>,
        established: &mut bool,
    ) -> Result<Consumed> {
        // Multipath duplicates of anything already consumed are dropped here.
        if self.store.is_seen(&env.content_id())? {
            return Ok(Consumed::Done);
        }
        match env.kind {
            EnvelopeKind::Fragment => {
                // Fragments never nest (we only fragment whole envelopes);
                // treat nested ones as malformed.
                if depth > 0 {
                    self.store.mark_seen(&env.content_id())?;
                    return Ok(Consumed::Done);
                }
                let completed = self.reassembler.insert(&env.body, now);
                self.store.mark_seen(&env.content_id())?;
                if let Ok(Some(payload)) = completed {
                    if let Ok(inner) = Envelope::decode(&payload) {
                        if let Consumed::Later =
                            self.consume(&inner, 1, now, rng, acks, established)?
                        {
                            // Reassembled before its session exists — stash
                            // the inner envelope for later ticks.
                            self.store.pending_push(&inner, now, rng)?;
                        }
                    }
                }
                Ok(Consumed::Done)
            }
            EnvelopeKind::Handshake => self.consume_handshake(env, now, rng, acks, established),
            EnvelopeKind::Message | EnvelopeKind::Receipt => {
                self.consume_ratchet(env, now, rng, acks)
            }
        }
    }

    fn consume_handshake(
        &mut self,
        env: &Envelope,
        now: u64,
        rng: &mut impl CryptoRngCore,
        acks: &mut Vec<([u8; 32], [u8; 16])>,
        established: &mut bool,
    ) -> Result<Consumed> {
        // Every failure below is permanent for this envelope (it cannot
        // become decryptable later), so it is marked seen and dropped —
        // parsers never panic, dropped flights never wedge the queue.
        let done = |node: &mut Self| -> Result<Consumed> {
            node.store.mark_seen(&env.content_id())?;
            Ok(Consumed::Done)
        };

        let Ok(init_bytes) = open_anonymous(&self.identity, HS_AD, &env.body) else {
            return done(self); // not addressed to us
        };
        let Ok(init) = InitialMessage::decode(&init_bytes) else {
            return done(self);
        };
        if init.spk_id != self.vault.spk_id || init.pqspk_id != self.vault.pqspk_id {
            return done(self); // references prekeys we no longer hold
        }
        let opk = match init.opk_id {
            Some(id) => match self.vault.opk(id) {
                Some(opk) => Some(opk),
                None => return done(self), // one-time prekey already consumed
            },
            None => None,
        };
        let spk = self.vault.spk();
        let pqspk = self.vault.pqspk()?;
        let Ok((session, first_payload)) =
            respond(&self.identity, &spk, &pqspk, opk.as_ref(), &init, now, rng)
        else {
            return done(self);
        };

        // Success: consume the one-time prekey, persist everything.
        if let Some(id) = init.opk_id {
            self.vault.remove_opk(id);
            self.store.put_prekeys(&self.vault.encode(), rng)?;
        }
        let peer = init.initiator.ed;
        if self.store.get_contact(&peer)?.is_none() {
            let identity =
                postcard::to_allocvec(&init.initiator).map_err(|_| NodeError::CorruptState)?;
            self.store.put_contact(
                &ContactRecord {
                    peer,
                    identity,
                    name: String::new(),
                    bundle: Vec::new(),
                    hints: Vec::new(),
                    verified: false,
                },
                rng,
            )?;
            self.events.push_back(Event::ContactAdded { peer });
        }
        self.store.put_session(&peer, &session, rng)?;
        self.sessions.insert(peer, session);
        *established = true;
        self.events.push_back(Event::SessionEstablished { peer });

        if let Ok(body) = unpad(&first_payload) {
            self.record_inbound(peer, body, now, rng)?;
            acks.push((peer, env.content_id()));
        }
        self.store.mark_seen(&env.content_id())?;
        Ok(Consumed::Done)
    }

    fn consume_ratchet(
        &mut self,
        env: &Envelope,
        now: u64,
        rng: &mut impl CryptoRngCore,
        acks: &mut Vec<([u8; 32], [u8; 16])>,
    ) -> Result<Consumed> {
        // No session recognizes this token yet → it may be for a session a
        // later handshake establishes. Stash, don't drop.
        let Some(peer) = self.match_session(&env.token, now) else {
            return Ok(Consumed::Later);
        };
        let done = |node: &mut Self| -> Result<Consumed> {
            node.store.mark_seen(&env.content_id())?;
            Ok(Consumed::Done)
        };
        let Ok(msg) = RatchetMessage::decode(&env.body) else {
            return done(self);
        };
        let Some(session) = self.sessions.get_mut(&peer) else {
            return Ok(Consumed::Later);
        };
        let Ok(plaintext) = session.decrypt(rng, now, &msg, &[]) else {
            // Tampered, or outside the skipped-key window — a permanent,
            // honest failure per the ratchet contract.
            return done(self);
        };
        self.store.put_session(&peer, session, rng)?;
        let Ok(body) = unpad(&plaintext) else {
            return done(self);
        };

        match env.kind {
            EnvelopeKind::Message => {
                self.record_inbound(peer, body, now, rng)?;
                acks.push((peer, env.content_id()));
            }
            EnvelopeKind::Receipt => {
                // Receipts are terminal: they are not themselves receipted.
                if let Ok(receipt) = ReceiptPayload::decode(&body) {
                    self.apply_receipt(&peer, &receipt, rng)?;
                }
            }
            _ => unreachable!("consume() routes only Message/Receipt here"),
        }
        self.store.mark_seen(&env.content_id())?;
        Ok(Consumed::Done)
    }

    fn record_inbound(
        &mut self,
        peer: [u8; 32],
        body: Vec<u8>,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        self.store.put_message(
            &MessageRecord {
                id,
                peer,
                direction: Direction::Inbound,
                state: DeliveryState::Received,
                timestamp: now,
                body: body.clone(),
                wire_id: None,
            },
            rng,
        )?;
        self.events.push_back(Event::MessageReceived {
            peer,
            id,
            timestamp: now,
            body,
        });
        Ok(())
    }

    fn apply_receipt(
        &mut self,
        peer: &[u8; 32],
        receipt: &ReceiptPayload,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        // Fragment NACKs (selective retransmission) are consumed by the
        // mesh transport milestone (M4); acks advance delivery state now.
        for record in self.store.messages_with(peer)? {
            let Some(wire_id) = record.wire_id else {
                continue;
            };
            let acked = receipt.acks.iter().any(|a| bool::from(a.ct_eq(&wire_id)));
            if acked
                && record.direction == Direction::Outbound
                && record.state != DeliveryState::Delivered
            {
                let mut updated = record;
                updated.state = DeliveryState::Delivered;
                self.store.update_message(&updated, rng)?;
                self.events.push_back(Event::DeliveryUpdated {
                    id: updated.id,
                    state: DeliveryState::Delivered,
                });
            }
        }
        Ok(())
    }

    /// Which session (if any) recognizes this delivery token, scanning a
    /// window of daily epochs so long-latency carriers still route.
    fn match_session(&self, token: &[u8; 32], now: u64) -> Option<[u8; 32]> {
        let today = epoch_day(now);
        let lo = today.saturating_sub(TOKEN_LOOKBACK_EPOCHS);
        let hi = today + TOKEN_LOOKAHEAD_EPOCHS;
        for (peer, session) in &self.sessions {
            let key = MailboxKey::from_bytes(*session.mailbox_key());
            for epoch in lo..=hi {
                if bool::from(delivery_token(&key, epoch).ct_eq(token)) {
                    return Some(*peer);
                }
            }
        }
        None
    }

    fn queue_receipt(
        &mut self,
        peer: &[u8; 32],
        acks: Vec<[u8; 16]>,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let Some(session) = self.sessions.get_mut(peer) else {
            return Ok(()); // session vanished — the sender will retry
        };
        let payload = ReceiptPayload {
            acks,
            nacks: Vec::new(),
        }
        .encode();
        let msg = session.encrypt(rng, now, &pad(&payload)?, &[]);
        let token = delivery_token(
            &MailboxKey::from_bytes(*session.mailbox_key()),
            epoch_day(now),
        );
        self.store.put_session(peer, session, rng)?;
        self.store.queue_push(
            &QueueItem {
                peer: *peer,
                msg_id: None,
                envelope: Envelope::new(EnvelopeKind::Receipt, token, msg.encode()),
            },
            rng,
        )?;
        Ok(())
    }

    // ---- send path (delivery engine + scheduler) ----------------------------

    async fn flush(&mut self, now: u64, rng: &mut impl CryptoRngCore) -> Result<()> {
        let transports = self.transports.clone();
        for (seq, item) in self.store.queue_all()? {
            if let Some(b) = self.backoff.get(&seq) {
                if now < b.next_ok {
                    continue;
                }
            }
            let hints = self.hints_for(&item.peer)?;

            // Scheduler: rank every (transport, hint) pair by reachability
            // (immediate beats store-and-forward), then latency, then cost.
            let mut candidates = Vec::new();
            for transport in &transports {
                let profile = transport.profile();
                for hint in &hints {
                    let rank = match transport.reachable(hint).await {
                        Reachability::Now => 0u8,
                        Reachability::StoreAndForward => 1,
                        Reachability::Unreachable => continue,
                    };
                    candidates.push((
                        (rank, profile.latency, profile.cost),
                        Arc::clone(transport),
                        hint.clone(),
                    ));
                }
            }
            candidates.sort_by_key(|(rank, _, _)| *rank);

            let mut sent = false;
            for (_, transport, hint) in &candidates {
                if send_via(transport.as_ref(), hint, &item.envelope)
                    .await
                    .is_ok()
                {
                    sent = true;
                    break;
                }
            }

            if sent {
                self.store.queue_ack(seq)?;
                self.backoff.remove(&seq);
                if let Some(msg_id) = item.msg_id {
                    self.mark_sent(&item.peer, &msg_id, rng)?;
                }
            } else {
                let entry = self.backoff.entry(seq).or_insert(Backoff {
                    attempts: 0,
                    next_ok: 0,
                });
                let delay = (RETRY_BASE_SECS << entry.attempts.min(7)).min(RETRY_CAP_SECS);
                entry.attempts = entry.attempts.saturating_add(1);
                entry.next_ok = now + delay;
            }
        }
        Ok(())
    }

    fn mark_sent(
        &mut self,
        peer: &[u8; 32],
        msg_id: &[u8; 16],
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        for record in self.store.messages_with(peer)? {
            if &record.id == msg_id && record.state == DeliveryState::Queued {
                let mut updated = record;
                updated.state = DeliveryState::Sent;
                self.store.update_message(&updated, rng)?;
                self.events.push_back(Event::DeliveryUpdated {
                    id: *msg_id,
                    state: DeliveryState::Sent,
                });
            }
        }
        Ok(())
    }

    fn hints_for(&self, peer: &[u8; 32]) -> Result<Vec<DeliveryHint>> {
        let Some(contact) = self.store.get_contact(peer)? else {
            return Ok(Vec::new());
        };
        Ok(contact
            .hints
            .iter()
            .filter_map(|bytes| postcard::from_bytes(bytes).ok())
            .collect())
    }
}

/// Hand one envelope to a transport, fragmenting if it exceeds the link MTU.
async fn send_via(
    transport: &dyn Transport,
    hint: &DeliveryHint,
    envelope: &Envelope,
) -> Result<()> {
    let mtu = transport.profile().mtu;
    let encoded = envelope.encode();
    if encoded.len() <= mtu {
        transport.send(hint, envelope).await?;
        return Ok(());
    }
    let budget = mtu
        .checked_sub(ENVELOPE_HEADER_LEN)
        .ok_or(NodeError::Protocol(
            kult_protocol::ProtocolError::MtuTooSmall,
        ))?;
    for body in fragment(&encoded, budget)? {
        transport
            .send(
                hint,
                &Envelope::new(EnvelopeKind::Fragment, envelope.token, body),
            )
            .await?;
    }
    Ok(())
}

fn encode_hints(hints: &[DeliveryHint]) -> Vec<Vec<u8>> {
    hints
        .iter()
        .map(|h| postcard::to_allocvec(h).expect("hint serialization cannot fail"))
        .collect()
}
