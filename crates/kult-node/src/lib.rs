//! Komms runtime (docs/03-architecture.md §2): composes the crypto core,
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
//!   ranking on failure; failed items retry with exponential backoff. The
//!   queue flushes in priority order (text > receipts > handshakes,
//!   docs/05-transports.md §4.2 rule 3), and payloads over 4 KiB are held
//!   off airtime-budgeted (LoRa) links with honest feedback instead of
//!   silently hogging the mesh.
//! - **Dedup & reassembly** — inbound envelopes are deduplicated by content
//!   id (multipath duplicates are normal), fragments reassembled, and
//!   envelopes that arrive before the session that can read them (courier
//!   reordering) are stashed persistently and retried — never lost, never
//!   double-processed. Partials stuck missing fragments are NACKed back to
//!   the sender, which retransmits exactly the missing indices (selective
//!   retransmission, §4.2 rule 2) — airtime is the scarcest resource in
//!   the system.
//!
//! Driving the node: applications call commands ([`Node::send_message`],
//! [`Node::add_contact`], … or the [`Command`] enum) and then pump
//! [`Node::tick`] — one receive/flush cycle — collecting [`Event`]s.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::Arc;

use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;

use kult_crypto::{
    initiate, open_anonymous, respond, safety_number, seal_anonymous, Identity, IdentityPublic,
    InitialMessage, KdfProfile, PrekeyBundle, RatchetMessage, SafetyNumber,
};
use kult_protocol::{
    decode_content, delivery_token, encode_text, epoch_day, fragment, intro_token,
    is_capability_control, pad, unpad, CapabilityControl, DecodedContent, Envelope, EnvelopeKind,
    FormatCapabilities, MailboxKey, Reassembler, ReceiptPayload, CONTENT_FORMAT_V1,
    CONTENT_KIND_ATTACHMENT, CONTENT_KIND_MENTION, CONTENT_KIND_TEXT, ENVELOPE_HEADER_LEN,
    REASSEMBLY_WINDOW_SECS,
};
use kult_store::{
    ContactRecord, ConversationId, ConversationMetadata, DeliveryState, Direction,
    LocalMetadataKey, LocalMetadataRecord, MessageRecord, NoteMessageRecord, QueueClass, QueueItem,
    ScheduledConversation as StoreScheduledConversation, ScheduledMessageRecord, Store,
};
use kult_transport::{CostClass, DeliveryHint, Discovery, Reachability, Transport};

mod api;
mod attachment;
mod carrier;
mod error;
mod groups;
mod labels;
mod vault;

pub use api::{
    AttachmentConversation, AttachmentDirection, AttachmentInfo, AttachmentMetadata,
    AttachmentObjectInfo, CarrierCapability, CarrierCapabilitySnapshot, Command, ContentStatus,
    Event, GroupInfo, GroupMentionCapability, LabelConversationInfo, LabelFilterInfo, LabelInfo,
    LabelMatchMode, MentionCapabilityIssue, MentionCapabilityIssueReason, MentionSpan,
    ScheduledConversation, ScheduledMessageInfo, StaleLabelInfo,
    StaleLabelReason as NodeStaleLabelReason,
};
pub use error::NodeError;
pub use kult_store::{
    ConversationId as LabelConversationId, LABEL_COLORS, MAX_LABELS, MAX_LABELS_PER_CONVERSATION,
    MAX_LABEL_ASSIGNMENTS, MAX_LOCAL_METADATA_STRING_BYTES, NOTE_TO_SELF_CONVERSATION_ID,
};

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

/// Future epochs of tokens handed to mailbox relays at check-in — how long
/// this node may stay offline while senders' deposits still match a
/// registered filter.
const MAILBOX_AHEAD_EPOCHS: u64 = 35;

/// Retention for inbound envelopes that cannot be consumed yet (arrived
/// before their session). Matches the bundle TTL: after a month the
/// handshake that would unlock them can no longer arrive either.
const PENDING_TTL_SECS: u64 = 30 * 86_400;

/// Retry backoff: base delay, doubling per attempt, capped.
const RETRY_BASE_SECS: u64 = 30;
const RETRY_CAP_SECS: u64 = 3_600;

/// Envelopes above this size never ride an airtime-budgeted (LoRa) link:
/// they are held for a faster carrier, with honest feedback
/// ([`Event::AwaitingFasterLink`]), instead of silently hogging the mesh
/// (docs/05-transports.md §4.2 rule 3).
const AIRTIME_CEILING_BYTES: usize = 4 * 1024;

/// How long a partial message may sit incomplete before the receiver NACKs
/// its missing fragment indices (selective retransmission,
/// docs/05-transports.md §4.2 rule 2) — long enough that in-flight
/// fragments on a seconds-class link get their chance to arrive.
const NACK_AFTER_SECS: u64 = 60;
/// Minimum spacing between NACKs for the same partial. NACKs cost airtime
/// too, and a duplicate retransmission costs even more.
const NACK_INTERVAL_SECS: u64 = 900;

/// Cap on remembered sent-fragment sets (the sender side of selective
/// retransmission). Oldest entries evict first; an evicted message can no
/// longer be selectively repaired, only fully resent.
const MAX_FRAG_CACHE: usize = 256;

// ---- bridging (docs/05-transports.md §4.2 rule 5, ADR-0009) ----------------

/// How long a transit envelope may wait for a sink before it is dropped.
/// Sized like the other store-and-forward windows: human-scale, but transit
/// lives in memory — the end-to-end retry machinery, not the bridge, is the
/// source of reliability.
const TRANSIT_TTL_SECS: u64 = 3 * 86_400;

/// Caps on the transit queue. Third parties fill it, so both axes bound it;
/// an envelope refused here is simply not bridged — the sealed traffic's own
/// retries may find another path or a later slot.
const MAX_TRANSIT_ITEMS: usize = 256;
const MAX_TRANSIT_BYTES: usize = 512 * 1024;

/// Remembered transit content ids (dedup across multipath echoes and
/// multi-bridge loops). Oldest forgotten first.
const MAX_TRANSIT_SEEN: usize = 4096;

/// Mesh→internet transit: how many deposit rounds before an envelope no
/// relay recognizes is dropped. Mesh-internal chatter matches no internet
/// registration ever; this bounds what such traffic can cost.
const TRANSIT_DEPOSIT_ATTEMPTS: u32 = 8;

/// Base retry delay for refused transit deposits, doubling per attempt. A
/// gentler schedule than the delivery engine's own queue: a refusal is one
/// tiny request on a metered link, and the common transient cause — the
/// recipient's *fresh* session tokens missing their first mailbox check-in
/// by seconds — clears quickly.
const TRANSIT_DEPOSIT_RETRY_BASE_SECS: u64 = 5;

/// Internet→mesh transit: total floods per envelope, and the base spacing
/// between them (doubling each round). Receipts are end-to-end and opaque
/// to the bridge, so there is no feedback channel — bounded blind
/// repetition stands in for retransmission (ADR-0009).
const TRANSIT_MESH_FLOODS: u32 = 3;
const TRANSIT_REFLOOD_BASE_SECS: u64 = 300;

/// Internet→mesh transit envelopes flooded per tick, so a deep transit
/// backlog never starves the bridge's own outbound queue of airtime (which
/// always flushes first).
const TRANSIT_MESH_PER_TICK: usize = 4;

/// Missing fragment indices per in-flight message id — the NACK half of a
/// receipt (the shape of [`ReceiptPayload::nacks`]).
type FragNacks = Vec<([u8; 4], Vec<u16>)>;

struct Backoff {
    attempts: u32,
    next_ok: u64,
}

/// Receiver-side bookkeeping for one in-flight partial message: enough to
/// address the NACK requesting its missing fragments (via the delivery
/// token) and to pace repeats.
struct PartialMeta {
    token: [u8; 32],
    first_seen: u64,
    last_nack: Option<u64>,
}

/// Sender-side copy of one fragmented envelope's fragment bodies, kept so a
/// NACK can trigger retransmission of exactly the missing indices instead of
/// re-flooding the whole message (docs/05-transports.md §4.2 rule 2).
struct SentFragments {
    peer: [u8; 32],
    token: [u8; 32],
    bodies: Vec<Vec<u8>>,
    sent_at: u64,
}

enum Consumed {
    /// Fully handled (or permanently unprocessable) — never seen again.
    Done,
    /// Cannot be processed *yet* (no matching session) — stash and retry.
    Later,
}

/// One third-party envelope in transit across the bridge (ADR-0009).
struct TransitItem {
    envelope: Envelope,
    /// Which side it arrived on — transit never returns to the carrier
    /// class it came from (split horizon).
    from_mesh: bool,
    first_seen: u64,
    attempts: u32,
    next_ok: u64,
}

/// Bridging state (docs/05-transports.md §4.2 rule 5, ADR-0009): the
/// bounded transit queue plus the internet-side deposit targets. The bridge
/// handles nothing but sealed envelopes and rotating tokens — the same view
/// any relay already has.
struct Bridge {
    /// Internet-side sinks for mesh-heard transit: mailbox relays to offer
    /// deposits to (the node's own mailbox service reachable among them).
    relays: Vec<DeliveryHint>,
    queue: VecDeque<TransitItem>,
    queue_bytes: usize,
    /// Content ids ever admitted — multipath echoes and multi-bridge loops
    /// die here. Insertion-ordered so the oldest forgets first.
    seen: HashSet<[u8; 16]>,
    seen_order: VecDeque<[u8; 16]>,
}

impl Bridge {
    fn new(relays: Vec<DeliveryHint>) -> Self {
        Self {
            relays,
            queue: VecDeque::new(),
            queue_bytes: 0,
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
        }
    }

    /// Admit one foreign envelope, if it is new and fits every cap.
    fn admit(&mut self, envelope: &Envelope, from_mesh: bool, now: u64) {
        let encoded_len = ENVELOPE_HEADER_LEN + envelope.body.len();
        // Anything over the airtime ceiling could neither ride the mesh nor
        // have come off it whole — never transit (§4.2 rule 3).
        if encoded_len > AIRTIME_CEILING_BYTES {
            return;
        }
        let id = envelope.content_id();
        if self.seen.contains(&id) {
            return;
        }
        if self.queue.len() >= MAX_TRANSIT_ITEMS
            || self.queue_bytes + encoded_len > MAX_TRANSIT_BYTES
        {
            return; // full: not remembered, so a later copy may still get in
        }
        self.seen.insert(id);
        self.seen_order.push_back(id);
        while self.seen_order.len() > MAX_TRANSIT_SEEN {
            if let Some(old) = self.seen_order.pop_front() {
                self.seen.remove(&old);
            }
        }
        self.queue_bytes += encoded_len;
        self.queue.push_back(TransitItem {
            envelope: envelope.clone(),
            from_mesh,
            first_seen: now,
            attempts: 0,
            next_ok: now,
        });
    }
}

/// The Komms runtime: one identity, one store, any number of transports.
pub struct Node {
    store: Store,
    identity: Identity,
    vault: PrekeyVault,
    transports: Vec<Arc<dyn Transport>>,
    discoveries: Vec<Arc<dyn Discovery>>,
    sessions: HashMap<[u8; 32], kult_crypto::Session>,
    capabilities_advertised: HashSet<[u8; 32]>,
    media_reconciled: bool,
    attachment_request_at: HashMap<[u8; 16], u64>,
    carrier_capabilities: HashMap<[u8; 32], CarrierCapabilitySnapshot>,
    reassembler: Reassembler,
    backoff: HashMap<i64, Backoff>,
    frag_meta: HashMap<[u8; 4], PartialMeta>,
    frag_cache: HashMap<[u8; 4], SentFragments>,
    held_notified: HashSet<i64>,
    bridge: Option<Bridge>,
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

    /// Restore a node from an encrypted backup file onto a **new** store at
    /// `path` (docs/07-storage.md §4): the exported identity resumes with
    /// contacts and history intact, prekeys are minted fresh (the old
    /// device's one-time prekeys must never be honored twice), and every
    /// peer that had a live session at export time re-handshakes on the
    /// first [`Node::tick`] — ratchet state is deliberately not portable.
    pub fn restore(
        path: &std::path::Path,
        backup: &[u8],
        mnemonic: &str,
        passphrase: &[u8],
        profile: KdfProfile,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self> {
        let store = Store::restore_backup(path, backup, mnemonic, passphrase, profile, rng)?;
        let identity = store.get_identity()?.ok_or(NodeError::CorruptState)?;
        let vault = PrekeyVault::generate(rng);
        store.put_prekeys(&vault.encode(), rng)?;
        Self::assemble(store, identity, vault)
    }

    /// Export this node's encrypted backup (docs/07-storage.md §4):
    /// identity + contacts + history + session-reset markers, sealed under
    /// a freshly minted 24-word mnemonic. Returns the file bytes and the
    /// mnemonic — show it to the user once; it is not stored anywhere.
    /// Ratchet sessions and prekey secrets are deliberately excluded;
    /// restoring re-handshakes instead ([`Node::restore`]).
    pub fn export_backup(
        &self,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Vec<u8>, zeroize::Zeroizing<String>)> {
        Ok(self.store.export_backup(now, rng)?)
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
            discoveries: Vec::new(),
            sessions,
            capabilities_advertised: HashSet::new(),
            media_reconciled: false,
            attachment_request_at: HashMap::new(),
            carrier_capabilities: HashMap::new(),
            reassembler: Reassembler::new(),
            backoff: HashMap::new(),
            frag_meta: HashMap::new(),
            frag_cache: HashMap::new(),
            held_notified: HashSet::new(),
            bridge: None,
            events: VecDeque::new(),
        })
    }

    /// Register a transport. Order does not matter — the scheduler ranks by
    /// link profile per delivery, not registration order.
    pub fn add_transport(&mut self, transport: Arc<dyn Transport>) {
        self.transports.push(transport);
    }

    /// Register a discovery plane (a DHT) for prekey-bundle publication and
    /// lookup. Registering none is fine — bundles then travel out-of-band
    /// only (QR, file), exactly as in M2.
    pub fn add_discovery(&mut self, discovery: Arc<dyn Discovery>) {
        self.discoveries.push(discovery);
    }

    /// Enable, reconfigure, or (`None`) disable internet↔mesh bridging
    /// (docs/05-transports.md §4.2 rule 5, ADR-0009). While enabled, sealed
    /// envelopes heard on airtime-class carriers whose delivery tokens this
    /// node does not recognize are offered as mailbox deposits to `relays`
    /// (a relay accepts exactly when the recipient registered that token
    /// there), and third-party envelopes surfaced by carriers via
    /// `recv_transit` are flooded on broadcast (mesh) carriers — after this
    /// node's own traffic, bounded in every axis. Off by default: bridging
    /// spends the operator's airtime and bandwidth on strangers' sealed
    /// traffic, so it is a deliberate choice.
    pub fn set_bridge(&mut self, relays: Option<Vec<DeliveryHint>>) {
        match relays {
            Some(relays) => match &mut self.bridge {
                Some(bridge) => bridge.relays = relays,
                None => self.bridge = Some(Bridge::new(relays)),
            },
            None => self.bridge = None,
        }
    }

    /// Third-party envelopes currently queued for bridging (0 when bridging
    /// is off) — observability for daemon status, nothing more.
    pub fn transit_queued(&self) -> usize {
        self.bridge.as_ref().map_or(0, |b| b.queue.len())
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

    // ---- discovery (DHT prekey records, docs/05-transports.md §2) -----------

    /// Publish this node's prekey bundle on every registered discovery
    /// plane, keyed by the digest inside our kult address — after this,
    /// anyone holding the address can start a session with no further
    /// out-of-band exchange.
    ///
    /// `hints` are our own reachable addresses (e.g.
    /// [`kult_transport::Libp2pTransport::listen_addrs`] as
    /// [`DeliveryHint::Multiaddr`]); they ride in the bundle's `relay_hints`
    /// so a fetcher learns both *who* we are and *where* to deliver.
    ///
    /// The published bundle deliberately carries **no one-time prekey**: a
    /// DHT record is served to arbitrarily many fetchers, and an OPK is
    /// single-use — the first handshake would consume it and strand everyone
    /// else. First-flight forward secrecy for DHT-initiated sessions rests
    /// on the signed prekeys, exactly as specified for OPK-less PQXDH
    /// (docs/04-cryptography.md §3). Call it again after rotating prekeys or
    /// when listen addresses change; the record replaces the previous one.
    pub async fn publish_bundle(&mut self, hints: &[DeliveryHint], now: u64) -> Result<()> {
        if self.discoveries.is_empty() {
            return Err(NodeError::NoDiscovery);
        }
        let bundle = PrekeyBundle::build(
            &self.identity,
            &self.vault.spk(),
            &self.vault.pqspk()?,
            None,
            now + BUNDLE_TTL_SECS,
            encode_hints(hints),
        );
        let key = self.identity.public().address_digest();
        let value = bundle.encode();
        let mut published = false;
        for discovery in &self.discoveries {
            if discovery.publish(key, value.clone()).await.is_ok() {
                published = true;
            }
        }
        if published {
            Ok(())
        } else {
            Err(NodeError::NoDiscovery)
        }
    }

    /// Add a contact from their kult address alone, fetching the prekey
    /// bundle from the discovery planes. Every candidate record is untrusted
    /// input: it must carry valid signatures **and** hash back to the very
    /// digest the address encodes, so a malicious DHT node can withhold a
    /// bundle but never substitute one. Among the survivors the freshest
    /// (latest-expiring) bundle wins, and its embedded delivery hints become
    /// the contact's hints. Returns the contact's peer id.
    pub async fn add_contact_by_address(
        &mut self,
        name: &str,
        address: &str,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 32]> {
        if self.discoveries.is_empty() {
            return Err(NodeError::NoDiscovery);
        }
        let digest = kult_crypto::parse_address(address)?;
        let bundle = self
            .lookup_bundle(digest, now)
            .await
            .ok_or(NodeError::BundleNotFound)?;
        let hints = decode_hints(&bundle.relay_hints);
        self.add_contact(name, &bundle.encode(), &hints, now, rng)
    }

    /// Fetch, verify, and select the freshest prekey bundle for `digest`
    /// across all discovery planes. `None` means no candidate survived
    /// verification — never that a record was accepted unverified.
    async fn lookup_bundle(&self, digest: [u8; 32], now: u64) -> Option<PrekeyBundle> {
        let mut best: Option<PrekeyBundle> = None;
        for discovery in &self.discoveries {
            let Ok(candidates) = discovery.lookup(digest).await else {
                continue;
            };
            for bytes in candidates {
                let Ok(bundle) = PrekeyBundle::decode(&bytes) else {
                    continue;
                };
                if bundle.verify(now).is_err() || bundle.identity.address_digest() != digest {
                    continue;
                }
                if best
                    .as_ref()
                    .is_none_or(|b| bundle.expires_at > b.expires_at)
                {
                    best = Some(bundle);
                }
            }
        }
        best
    }

    /// The "accept mail for these" filter set (docs/04-cryptography.md §7)
    /// this node hands its chosen mailbox relays via
    /// [`kult_transport::Libp2pTransport::mailbox_checkin`]: introduction
    /// tokens (so first-contact handshakes can be deposited) plus every
    /// session's delivery tokens, over a window reaching
    /// `TOKEN_LOOKBACK_EPOCHS` back (deposits may be old) and
    /// `MAILBOX_AHEAD_EPOCHS` forward (deposits keep landing while this node
    /// is offline). Every token is scoped to this node as recipient
    /// (ADR-0007), so a check-in can only ever drain mail addressed to us.
    pub fn mailbox_tokens(&self, now: u64) -> Vec<[u8; 32]> {
        let me = self.identity.public().ed;
        let today = epoch_day(now);
        let lo = today.saturating_sub(TOKEN_LOOKBACK_EPOCHS);
        let hi = today + MAILBOX_AHEAD_EPOCHS;
        let mut tokens = Vec::new();
        for epoch in lo..=hi {
            tokens.push(intro_token(&me, epoch));
            for session in self.sessions.values() {
                tokens.push(delivery_token(
                    &MailboxKey::from_bytes(*session.mailbox_key()),
                    epoch,
                    &me,
                ));
            }
        }
        tokens
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

    /// Text history in the one reserved device-local note-to-self
    /// conversation, in insertion order.
    pub fn note_to_self_messages(&self) -> Result<Vec<NoteMessageRecord>> {
        Ok(self.store.note_messages()?)
    }

    /// Number of envelopes waiting in the outbound queue.
    pub fn queued(&self) -> Result<usize> {
        Ok(self.store.queue_all()?.len())
    }

    /// Messages waiting for an absolute UTC activation instant.
    pub fn scheduled_messages(&self) -> Result<Vec<ScheduledMessageInfo>> {
        Ok(self
            .store
            .scheduled_messages()?
            .into_iter()
            .map(scheduled_info)
            .collect())
    }

    // ---- commands ----------------------------------------------------------

    /// Execute one [`Command`] — the single serializable entry point the FFI
    /// layer wraps. Effects surface as [`Event`]s on the next [`Node::tick`].
    pub fn execute(&mut self, cmd: Command, now: u64, rng: &mut impl CryptoRngCore) -> Result<()> {
        match cmd {
            Command::Send { peer, body } => {
                self.send_message(&peer, &body, now, rng)?;
            }
            Command::Schedule {
                peer,
                body,
                not_before,
            } => {
                self.schedule_message(&peer, &body, not_before, now, rng)?;
            }
            Command::GroupSchedule {
                group,
                body,
                not_before,
            } => {
                self.schedule_group_message(&group, &body, not_before, now, rng)?;
            }
            Command::ScheduledEdit {
                id,
                body,
                not_before,
            } => self.edit_scheduled_message(&id, &body, not_before, now, rng)?,
            Command::ScheduledCancel { id } => self.cancel_scheduled_message(&id)?,
            Command::NoteToSelfSend { body } => {
                self.note_to_self_send(&body, now, rng)?;
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
            Command::GroupCreate { name, members } => {
                self.create_group(&name, &members, rng)?;
            }
            Command::GroupSend { group, body } => {
                self.group_send(&group, &body, now, rng)?;
            }
            Command::GroupMentionSend {
                group,
                text,
                spans,
                review_token,
            } => {
                self.group_send_mention(&group, &text, &spans, review_token, now, rng)?;
            }
            Command::GroupAdd { group, peer } => self.group_add(&group, &peer, rng)?,
            Command::GroupRemove { group, peer } => self.group_remove(&group, &peer, now, rng)?,
            Command::GroupLeave { group } => self.group_leave(&group, now, rng)?,
            Command::AttachmentAccept { transfer } => {
                self.accept_attachment(&transfer, now, rng)?
            }
            Command::AttachmentReject { transfer } => {
                self.reject_attachment(&transfer, now, rng)?
            }
            Command::AttachmentCancel { transfer } => {
                self.cancel_attachment(&transfer, now, rng)?
            }
            Command::AttachmentPause { transfer } => self.pause_attachment(&transfer, now, rng)?,
            Command::AttachmentResume { transfer } => {
                self.resume_attachment(&transfer, now, rng)?
            }
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
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        self.send_message_with_id(peer, body, id, now, now, rng)
    }

    fn send_message_with_id(
        &mut self,
        peer: &[u8; 32],
        body: &[u8],
        id: [u8; 16],
        timestamp: u64,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        // Mention is permanently group-only. Reject a canonical frame before
        // it can enter pairwise history, padding, encryption, or the queue.
        if matches!(decode_content(body), DecodedContent::Mention { .. }) {
            return Err(NodeError::InvalidMention);
        }
        let contact = self
            .store
            .get_contact(peer)?
            .ok_or(NodeError::UnknownPeer)?;

        // The anonymous first flight is always legacy text. Once a live
        // session has authenticated v1 Text support, reuse the record id as
        // the framed content id and retain those exact bytes in history.
        let wire_body = if self.sessions.contains_key(peer)
            && core::str::from_utf8(body).is_ok()
            && self.peer_supports_text(peer)?
        {
            encode_text(id, core::str::from_utf8(body).expect("checked above"))?
        } else {
            body.to_vec()
        };
        let mut record = MessageRecord {
            id,
            peer: *peer,
            direction: Direction::Outbound,
            state: DeliveryState::Queued,
            timestamp,
            body: wire_body.clone(),
            wire_id: None,
        };
        self.store.put_message(&record, rng)?;
        self.events.push_back(Event::DeliveryUpdated {
            id,
            state: DeliveryState::Queued,
        });

        let padded = pad(&wire_body)?;
        let envelope = if let Some(session) = self.sessions.get_mut(peer) {
            let msg = session.encrypt(rng, now, &padded, &[]);
            let token = delivery_token(
                &MailboxKey::from_bytes(*session.mailbox_key()),
                epoch_day(now),
                peer,
            );
            self.store.put_session(peer, session, rng)?;
            Envelope::new(EnvelopeKind::Message, token, msg.encode())
        } else {
            if contact.bundle.is_empty() {
                return Err(NodeError::NoSession);
            }
            self.initiate_session(peer, &contact.bundle, &padded, now, rng)?
        };

        record.wire_id = Some(envelope.content_id());
        self.store.update_message(&record, rng)?;
        self.store.queue_push(
            &QueueItem {
                peer: *peer,
                msg_id: Some(id),
                group_msg_id: None,
                class: QueueClass::Normal,
                envelope,
            },
            rng,
        )?;
        Ok(id)
    }

    /// Persist pairwise text until `not_before` UTC. No ratchet, envelope,
    /// queue, or transport state is touched before activation.
    pub fn schedule_message(
        &mut self,
        peer: &[u8; 32],
        body: &[u8],
        not_before: u64,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        let contact = self
            .store
            .get_contact(peer)?
            .ok_or(NodeError::UnknownPeer)?;
        if !self.sessions.contains_key(peer) && contact.bundle.is_empty() {
            return Err(NodeError::NoSession);
        }
        self.schedule(
            StoreScheduledConversation::Peer(*peer),
            body,
            not_before,
            now,
            rng,
        )
    }

    /// Persist group text until `not_before` UTC without advancing the
    /// sender chain or creating member copies early.
    pub fn schedule_group_message(
        &mut self,
        group: &[u8; 32],
        body: &[u8],
        not_before: u64,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        self.store
            .get_group(group)?
            .ok_or(NodeError::UnknownGroup)?;
        self.schedule(
            StoreScheduledConversation::Group(*group),
            body,
            not_before,
            now,
            rng,
        )
    }

    fn schedule(
        &mut self,
        conversation: StoreScheduledConversation,
        body: &[u8],
        not_before: u64,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        if not_before <= now || core::str::from_utf8(body).is_err() || pad(body).is_err() {
            return Err(NodeError::InvalidSchedule);
        }
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        self.store.put_scheduled_message(
            &ScheduledMessageRecord {
                id,
                conversation,
                created_at: now,
                not_before,
                body: body.to_vec(),
            },
            rng,
        )?;
        self.events.push_back(Event::ScheduledMessageUpdated { id });
        Ok(id)
    }

    /// Replace a scheduled message's body and UTC instant. Once activation
    /// begins the scheduled row is gone and edits fail explicitly.
    pub fn edit_scheduled_message(
        &mut self,
        id: &[u8; 16],
        body: &[u8],
        not_before: u64,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        if not_before <= now || core::str::from_utf8(body).is_err() || pad(body).is_err() {
            return Err(NodeError::InvalidSchedule);
        }
        let mut record = self
            .store
            .get_scheduled_message(id)?
            .ok_or(NodeError::UnknownScheduledMessage)?;
        record.body = body.to_vec();
        record.not_before = not_before;
        if !self.store.update_scheduled_message(&record, rng)? {
            return Err(NodeError::UnknownScheduledMessage);
        }
        self.events
            .push_back(Event::ScheduledMessageUpdated { id: *id });
        Ok(())
    }

    /// Cancel a scheduled message before its activation instant.
    pub fn cancel_scheduled_message(&mut self, id: &[u8; 16]) -> Result<()> {
        if !self.store.delete_scheduled_message(id)? {
            return Err(NodeError::UnknownScheduledMessage);
        }
        self.events
            .push_back(Event::ScheduledMessageCancelled { id: *id });
        Ok(())
    }

    /// Append UTF-8 text to the one reserved local note-to-self
    /// conversation. This path creates no contact, session, envelope,
    /// receipt, delivery state, queue item, or transport work.
    pub fn note_to_self_send(
        &mut self,
        body: &str,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<[u8; 16]> {
        if self
            .store
            .get_local_metadata(&LocalMetadataKey::Conversation(ConversationId::NoteToSelf))?
            .is_none()
        {
            self.store.put_local_metadata(
                &LocalMetadataRecord::Conversation(ConversationMetadata {
                    conversation: ConversationId::NoteToSelf,
                    created_at: now,
                }),
                rng,
            )?;
        }
        let mut id = [0u8; 16];
        rng.fill_bytes(&mut id);
        let record = NoteMessageRecord {
            id,
            timestamp: now,
            body: body.to_owned(),
        };
        self.store.put_note_message(&record, rng)?;
        self.events.push_back(Event::NoteToSelfMessageAdded {
            id,
            timestamp: now,
            body: body.to_owned(),
        });
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
        if !self.media_reconciled {
            self.store.reconcile_media(rng)?;
            self.media_reconciled = true;
        }
        // 0. Session-reset markers (a restore happened): queue fresh
        //    handshakes so re-keyed traffic flows without waiting for the
        //    user to send first.
        self.rekey_reset_peers(now, rng)?;

        // Absolute UTC scheduling is enforced in core before encryption:
        // clock rollback keeps entries held, clock advance activates them on
        // this tick, and a restart simply reloads the same sealed records.
        self.activate_scheduled_messages(now, rng)?;

        // Loaded and newly-created sessions advertise on the first tick.
        // Controls use the durable queue and are terminal like receipts.
        self.advertise_capabilities(now, rng)?;

        // 1. Gather: previously-stashed envelopes first, then fresh arrivals.
        //    When bridging, fresh arrivals with tokens this node does not
        //    recognize also enter the transit queue (ADR-0009): mesh-heard
        //    foreignness heads for the internet, carrier-surfaced transit
        //    (bridge mailbox deposits) heads for the mesh. Every arrival
        //    still joins the normal receive path — "foreign" and "ours, but
        //    the unlocking handshake hasn't arrived yet" are indistinguishable
        //    by design, and downstream dedup absorbs the overlap.
        let mut work: Vec<(Envelope, u64)> = self.store.pending_drain()?;
        let transports = self.transports.clone();
        for transport in &transports {
            let airtime = transport.profile().cost == CostClass::Airtime;
            // A dead link must not stall the others; its envelopes will
            // arrive via retry or another path.
            if let Ok(envelopes) = transport.recv().await {
                for envelope in envelopes {
                    if airtime && self.bridge.is_some() && !self.token_is_mine(&envelope.token, now)
                    {
                        if let Some(bridge) = &mut self.bridge {
                            bridge.admit(&envelope, true, now);
                        }
                    }
                    work.push((envelope, now));
                }
            }
            if self.bridge.is_some() {
                if let Ok(envelopes) = transport.recv_transit().await {
                    for envelope in envelopes {
                        if !self.token_is_mine(&envelope.token, now) {
                            if let Some(bridge) = &mut self.bridge {
                                bridge.admit(&envelope, false, now);
                            }
                        }
                        work.push((envelope, now));
                    }
                }
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

        // 2b. Group upkeep (ADR-0012): flush due announces (initiating
        //     pairwise sessions where possible) and serve late fan-out to
        //     members whose session appeared after a group send.
        self.tick_groups(now, rng).await?;

        // 2c. Publish one authoritative, expiring carrier verdict per peer.
        //     Attachment activation consumes this exact snapshot rather than
        //     independently inferring capacity from a route.
        self.refresh_carrier_capabilities(now, rng).await?;

        // 2d. Attachment offers and resumable missing-range requests activate
        //     only under a fresh F4 bulk-capable verdict.
        self.activate_attachment_transfers(now, rng).await?;

        // 3. Acknowledge consumed messages with end-to-end encrypted
        //    receipts, and NACK the missing fragment indices of stale
        //    partials (selective retransmission, docs/05-transports.md §4.2
        //    rule 2) — batched per peer, acks and nacks in one envelope.
        let mut acks_by_peer: BTreeMap<[u8; 32], Vec<[u8; 16]>> = BTreeMap::new();
        for (peer, content_id) in acks {
            acks_by_peer.entry(peer).or_default().push(content_id);
        }
        let mut nacks_by_peer: BTreeMap<[u8; 32], FragNacks> = BTreeMap::new();
        for (id, missing) in self.stale_partials(now) {
            // The fragment's delivery token names the session to ask.
            // Handshake fragments never match one — correctly so: with no
            // session there is nothing to encrypt a receipt under.
            let Some(token) = self.frag_meta.get(&id).map(|m| m.token) else {
                continue;
            };
            let Some(peer) = self.match_session(&token, now) else {
                continue;
            };
            if let Some(meta) = self.frag_meta.get_mut(&id) {
                meta.last_nack = Some(now);
            }
            nacks_by_peer.entry(peer).or_default().push((id, missing));
        }
        let receipt_peers: BTreeSet<[u8; 32]> = acks_by_peer
            .keys()
            .chain(nacks_by_peer.keys())
            .copied()
            .collect();
        for peer in receipt_peers {
            let acks = acks_by_peer.remove(&peer).unwrap_or_default();
            let nacks = nacks_by_peer.remove(&peer).unwrap_or_default();
            self.queue_receipt(&peer, acks, nacks, now, rng)?;
        }

        // 4. Flush the outbound queue, then — only with whatever airtime and
        //    attention is left — third-party transit (ADR-0009).
        self.flush(now, rng).await?;
        self.flush_transit(now).await;

        Ok(self.drain_events())
    }

    /// Establish a fresh outbound session from a contact's stored prekey
    /// bundle, sealing the (already padded) first payload into the
    /// anonymous handshake flight. A reset-marked peer (post-restore) gets
    /// the OPK-less mode: the old device consumed the archived bundle's
    /// one-time prekey, so referencing it again would only get the flight
    /// dropped by the peer's vault.
    fn initiate_session(
        &mut self,
        peer: &[u8; 32],
        bundle_bytes: &[u8],
        padded: &[u8],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Envelope> {
        let mut bundle = PrekeyBundle::decode(bundle_bytes)?.verify(now)?;
        if self.store.reset_markers()?.contains(peer) {
            bundle = bundle.without_opk();
        }
        let (session, init) = initiate(&self.identity, &bundle, padded, now, rng)?;
        let sealed = seal_anonymous(&bundle.bundle().identity, HS_AD, &init.encode(), rng);
        self.store.delete_capabilities(peer)?;
        self.capabilities_advertised.remove(peer);
        self.store.put_session(peer, &session, rng)?;
        self.sessions.insert(*peer, session);
        Ok(Envelope::new(
            EnvelopeKind::Handshake,
            intro_token(peer, epoch_day(now)),
            sealed,
        ))
    }

    fn activate_scheduled_messages(
        &mut self,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        for scheduled in self.store.scheduled_messages()? {
            if now < scheduled.not_before {
                continue;
            }
            let activation = (|| -> Result<()> {
                match scheduled.conversation {
                    StoreScheduledConversation::Peer(peer) => {
                        // Validate a first-flight bundle before the ordinary
                        // send path persists its queued history record. An
                        // expired bundle keeps the editable scheduled record
                        // intact without stalling unrelated node work.
                        if !self.sessions.contains_key(&peer) {
                            let contact = self
                                .store
                                .get_contact(&peer)?
                                .ok_or(NodeError::UnknownPeer)?;
                            if contact.bundle.is_empty() {
                                return Err(NodeError::NoSession);
                            }
                            PrekeyBundle::decode(&contact.bundle)?.verify(now)?;
                        }
                        self.send_message_with_id(
                            &peer,
                            &scheduled.body,
                            scheduled.id,
                            scheduled.not_before,
                            now,
                            rng,
                        )?;
                    }
                    StoreScheduledConversation::Group(group) => {
                        self.group_send_with_id(
                            &group,
                            &scheduled.body,
                            scheduled.id,
                            scheduled.not_before,
                            now,
                            rng,
                        )?;
                    }
                }
                Ok(())
            })();
            if activation.is_err() {
                continue;
            }
            self.store.delete_scheduled_message(&scheduled.id)?;
            self.events
                .push_back(Event::ScheduledMessageActivated { id: scheduled.id });
        }
        Ok(())
    }

    /// Queue a fresh handshake to every session-reset-marked peer
    /// (docs/07-storage.md §4). A restored device's ratchets are gone;
    /// waiting for the user to send first would leave inbound traffic dead
    /// until then, so the reset markers the backup carried are turned into
    /// proactive re-handshakes — empty first flights the receiver
    /// recognizes as session maintenance, not messages. One attempt per
    /// marker: peers whose bundle is missing or expired fall back to the
    /// send-path auto-handshake once the user has a fresh bundle for them.
    fn rekey_reset_peers(&mut self, now: u64, rng: &mut impl CryptoRngCore) -> Result<()> {
        for peer in self.store.reset_markers()? {
            if self.sessions.contains_key(&peer) {
                // A send or an inbound handshake already re-keyed it.
                self.store.clear_reset_marker(&peer)?;
                continue;
            }
            let contact = self.store.get_contact(&peer)?;
            let Some(contact) = contact.filter(|c| !c.bundle.is_empty()) else {
                self.store.clear_reset_marker(&peer)?;
                continue;
            };
            // The marker must still be set while initiating — it selects
            // the OPK-less mode — and clears whatever the outcome.
            let flight = self.initiate_session(&peer, &contact.bundle, &pad(&[])?, now, rng);
            self.store.clear_reset_marker(&peer)?;
            let Ok(envelope) = flight else {
                continue; // e.g. the bundle expired since the backup
            };
            self.store.queue_push(
                &QueueItem {
                    peer,
                    msg_id: None,
                    group_msg_id: None,
                    class: QueueClass::Normal,
                    envelope,
                },
                rng,
            )?;
        }
        Ok(())
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
                // Remember which delivery token this partial rides under so
                // the NACK for its missing pieces (selective retransmission,
                // docs/05-transports.md §4.2 rule 2) knows which session to
                // ask — resolvable lazily, once that session exists.
                if env.body.len() >= 4 {
                    let id: [u8; 4] = env.body[..4].try_into().expect("length checked");
                    self.frag_meta.entry(id).or_insert(PartialMeta {
                        token: env.token,
                        first_seen: now,
                        last_nack: None,
                    });
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
            EnvelopeKind::Message | EnvelopeKind::Receipt | EnvelopeKind::GroupControl => {
                self.consume_ratchet(env, now, rng, acks, established)
            }
            EnvelopeKind::GroupMessage => self.consume_group_message(env, now, rng, acks),
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
        self.store.delete_capabilities(&peer)?;
        self.capabilities_advertised.remove(&peer);
        self.sessions.insert(peer, session);
        *established = true;
        self.events.push_back(Event::SessionEstablished { peer });
        // A re-established session may mean the peer restored from backup
        // and lost every group receiving chain: make sure any group we
        // share owes them an announce (ADR-0012).
        self.groups_on_session_established(&peer, rng)?;

        // An empty first flight is session maintenance (a re-handshake
        // after restore), not a message — nothing to record or receipt.
        if let Ok(body) = unpad(&first_payload) {
            if !body.is_empty() {
                self.record_inbound(peer, body, now, rng)?;
                acks.push((peer, env.content_id()));
            }
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
        established: &mut bool,
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
                if kult_protocol::is_attachment_bulk_record(&body) {
                    self.apply_attachment_bulk(peer, &body, now, rng)?;
                } else if is_capability_control(&body) {
                    if let Ok(capabilities) = CapabilityControl::decode(&body) {
                        self.store.put_capabilities(&peer, &capabilities, rng)?;
                        if !self.capabilities_advertised.contains(&peer) {
                            self.queue_capabilities(&peer, now, rng)?;
                        }
                    }
                } else if let Ok(receipt) = ReceiptPayload::decode(&body) {
                    self.apply_receipt(&peer, &receipt, rng)?;
                }
            }
            EnvelopeKind::GroupControl => {
                // Applied controls are acknowledged like messages;
                // not-applicable-yet ones (a co-member's announce racing
                // the creator's invite) are dropped *unacked* so the
                // sender's paced resend arrives after the missing context.
                if self.apply_group_control(peer, &body, now, rng, established)? {
                    acks.push((peer, env.content_id()));
                }
            }
            _ => unreachable!("consume() routes only Message/Receipt/GroupControl here"),
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
        let decoded = decode_content(&body);
        if let DecodedContent::Text { id, .. }
        | DecodedContent::Attachment { id, .. }
        | DecodedContent::Mention { id, .. } = decoded
        {
            let duplicate = self.store.messages_with(&peer)?.iter().any(|record| {
                record.direction == Direction::Inbound
                    && matches!(
                        decode_content(&record.body),
                        DecodedContent::Text { id: stored_id, .. }
                            | DecodedContent::Attachment { id: stored_id, .. }
                            | DecodedContent::Mention { id: stored_id, .. }
                            if stored_id == id
                    )
            });
            if duplicate {
                return Ok(());
            }
        }
        let (id, event_body, content) = match decoded {
            DecodedContent::LegacyText(text) => {
                let mut id = [0u8; 16];
                rng.fill_bytes(&mut id);
                (id, text.as_bytes().to_vec(), ContentStatus::LegacyText)
            }
            DecodedContent::Text { id, text } => {
                (id, text.as_bytes().to_vec(), ContentStatus::Text { id })
            }
            DecodedContent::Attachment { id, manifest } => {
                let transfer =
                    self.record_pairwise_attachment_offer(peer, id, &manifest, now, rng)?;
                (id, Vec::new(), ContentStatus::Attachment { id, transfer })
            }
            // Mention is group-only. Retain exact authenticated bytes as a
            // malformed pairwise record and never surface spans or notify.
            DecodedContent::Mention { .. } => {
                let mut id = [0u8; 16];
                rng.fill_bytes(&mut id);
                (id, Vec::new(), ContentStatus::Malformed)
            }
            DecodedContent::Unsupported {
                format_version,
                kind,
            } => {
                let mut id = [0u8; 16];
                rng.fill_bytes(&mut id);
                (
                    id,
                    Vec::new(),
                    ContentStatus::Unsupported {
                        format_version,
                        kind,
                    },
                )
            }
            DecodedContent::Malformed => {
                let mut id = [0u8; 16];
                rng.fill_bytes(&mut id);
                (id, Vec::new(), ContentStatus::Malformed)
            }
        };
        self.store.put_message(
            &MessageRecord {
                id,
                peer,
                direction: Direction::Inbound,
                state: DeliveryState::Received,
                timestamp: now,
                body,
                wire_id: None,
            },
            rng,
        )?;
        self.events.push_back(Event::MessageReceived {
            peer,
            id,
            timestamp: now,
            body: event_body,
            content,
        });
        Ok(())
    }

    fn peer_supports_text(&self, peer: &[u8; 32]) -> Result<bool> {
        Ok(self
            .store
            .get_capabilities(peer)?
            .is_some_and(|capabilities| {
                capabilities.supports(CONTENT_FORMAT_V1, CONTENT_KIND_TEXT)
            }))
    }

    fn local_capabilities() -> CapabilityControl {
        CapabilityControl {
            formats: vec![FormatCapabilities {
                format_version: CONTENT_FORMAT_V1,
                kinds: vec![
                    CONTENT_KIND_TEXT,
                    CONTENT_KIND_ATTACHMENT,
                    CONTENT_KIND_MENTION,
                ],
            }],
        }
    }

    fn advertise_capabilities(&mut self, now: u64, rng: &mut impl CryptoRngCore) -> Result<()> {
        let due: Vec<[u8; 32]> = self
            .sessions
            .keys()
            .filter(|peer| !self.capabilities_advertised.contains(*peer))
            .copied()
            .collect();
        for peer in due {
            self.queue_capabilities(&peer, now, rng)?;
        }
        Ok(())
    }

    fn queue_capabilities(
        &mut self,
        peer: &[u8; 32],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        let Some(session) = self.sessions.get_mut(peer) else {
            return Ok(());
        };
        let payload = Self::local_capabilities().encode()?;
        let msg = session.encrypt(rng, now, &pad(&payload)?, &[]);
        let token = delivery_token(
            &MailboxKey::from_bytes(*session.mailbox_key()),
            epoch_day(now),
            peer,
        );
        self.store.put_session(peer, session, rng)?;
        self.store.queue_push(
            &QueueItem {
                peer: *peer,
                msg_id: None,
                group_msg_id: None,
                class: QueueClass::Normal,
                envelope: Envelope::new(EnvelopeKind::Receipt, token, msg.encode()),
            },
            rng,
        )?;
        self.capabilities_advertised.insert(*peer);
        Ok(())
    }

    fn apply_receipt(
        &mut self,
        peer: &[u8; 32],
        receipt: &ReceiptPayload,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        // Selective retransmission (docs/05-transports.md §4.2 rule 2):
        // re-queue exactly the missing fragment indices, never the whole
        // message — and only if the NACK comes from the peer the fragments
        // were addressed to, so no one else can elicit retransmissions.
        // A stale NACK crossing a retransmission in flight re-queues
        // duplicates; the receiver's content-id dedup absorbs them.
        for (id, indices) in &receipt.nacks {
            let Some(cached) = self.frag_cache.get(id) else {
                continue; // expired or evicted — the full-message retry path remains
            };
            if !bool::from(cached.peer.ct_eq(peer)) {
                continue;
            }
            for &i in indices {
                let Some(body) = cached.bodies.get(usize::from(i)) else {
                    continue;
                };
                self.store.queue_push(
                    &QueueItem {
                        peer: *peer,
                        msg_id: None,
                        group_msg_id: None,
                        class: QueueClass::Normal,
                        envelope: Envelope::new(EnvelopeKind::Fragment, cached.token, body.clone()),
                    },
                    rng,
                )?;
            }
        }

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

        // The same acks may retire pending group announces and advance
        // per-member group deliveries (ADR-0012).
        self.apply_group_receipt(peer, &receipt.acks, rng)?;
        Ok(())
    }

    /// Which session (if any) recognizes this delivery token, scanning a
    /// window of daily epochs so long-latency carriers still route. Tokens
    /// are recipient-scoped (ADR-0007), so only envelopes addressed to *this*
    /// node match — never multipath echoes of our own outbound.
    fn match_session(&self, token: &[u8; 32], now: u64) -> Option<[u8; 32]> {
        let me = self.identity.public().ed;
        let today = epoch_day(now);
        let lo = today.saturating_sub(TOKEN_LOOKBACK_EPOCHS);
        let hi = today + TOKEN_LOOKAHEAD_EPOCHS;
        for (peer, session) in &self.sessions {
            let key = MailboxKey::from_bytes(*session.mailbox_key());
            for epoch in lo..=hi {
                if bool::from(delivery_token(&key, epoch, &me).ct_eq(token)) {
                    return Some(*peer);
                }
            }
        }
        None
    }

    /// Whether this delivery token addresses *this* node at all: a session
    /// token some ratchet recognizes, or one of our own introduction tokens
    /// (an inbound handshake) over the same epoch window. The bridging
    /// foreignness test (ADR-0009) — everything it cannot claim is transit.
    fn token_is_mine(&self, token: &[u8; 32], now: u64) -> bool {
        if self.match_session(token, now).is_some() {
            return true;
        }
        let me = self.identity.public().ed;
        let today = epoch_day(now);
        let lo = today.saturating_sub(TOKEN_LOOKBACK_EPOCHS);
        let hi = today + TOKEN_LOOKAHEAD_EPOCHS;
        (lo..=hi).any(|epoch| bool::from(intro_token(&me, epoch).ct_eq(token)))
    }

    /// Partials incomplete for at least [`NACK_AFTER_SECS`] (and not NACKed
    /// within [`NACK_INTERVAL_SECS`]), with their missing indices — the
    /// batch worth requesting selective retransmission for this tick. Also
    /// prunes metadata for partials the reassembler no longer tracks
    /// (completed, or expired out of the 24 h window).
    fn stale_partials(&mut self, now: u64) -> FragNacks {
        let missing = self.reassembler.missing(now);
        let live: HashSet<[u8; 4]> = missing.iter().map(|(id, _)| *id).collect();
        self.frag_meta.retain(|id, _| live.contains(id));
        missing
            .into_iter()
            .filter(|(id, miss)| {
                if miss.is_empty() {
                    return false;
                }
                let Some(meta) = self.frag_meta.get(id) else {
                    return false;
                };
                now.saturating_sub(meta.first_seen) >= NACK_AFTER_SECS
                    && meta
                        .last_nack
                        .is_none_or(|t| now.saturating_sub(t) >= NACK_INTERVAL_SECS)
            })
            .collect()
    }

    fn queue_receipt(
        &mut self,
        peer: &[u8; 32],
        acks: Vec<[u8; 16]>,
        nacks: FragNacks,
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<()> {
        if acks.is_empty() && nacks.is_empty() {
            return Ok(());
        }
        let Some(session) = self.sessions.get_mut(peer) else {
            return Ok(()); // session vanished — the sender will retry
        };
        let payload = ReceiptPayload { acks, nacks }.encode();
        let msg = session.encrypt(rng, now, &pad(&payload)?, &[]);
        let token = delivery_token(
            &MailboxKey::from_bytes(*session.mailbox_key()),
            epoch_day(now),
            peer,
        );
        self.store.put_session(peer, session, rng)?;
        self.store.queue_push(
            &QueueItem {
                peer: *peer,
                msg_id: None,
                group_msg_id: None,
                class: QueueClass::Normal,
                envelope: Envelope::new(EnvelopeKind::Receipt, token, msg.encode()),
            },
            rng,
        )?;
        Ok(())
    }

    // ---- send path (delivery engine + scheduler) ----------------------------

    async fn flush(&mut self, now: u64, rng: &mut impl CryptoRngCore) -> Result<()> {
        let transports = self.transports.clone();
        // Priority classes (docs/05-transports.md §4.2 rule 3): when a
        // scarce link finally opens, text goes first, then receipts, then
        // handshakes — FIFO within each class.
        let mut queue = self.store.queue_all()?;
        queue.sort_by_key(|(seq, item)| (flush_class(item.envelope.kind), *seq));
        for (seq, item) in queue {
            if let Some(b) = self.backoff.get(&seq) {
                if now < b.next_ok {
                    continue;
                }
            }
            let hints = self.resolve_hints(&item.peer, now, rng).await?;
            let oversize = item.envelope.encode().len() > AIRTIME_CEILING_BYTES;
            let mut held_for_airtime = false;

            // Scheduler: rank every (transport, hint) pair by reachability
            // (immediate beats store-and-forward), then latency, then cost.
            let mut candidates = Vec::new();
            for transport in &transports {
                let profile = transport.profile();
                // Rule 3: media-sized payloads never hog the mesh — hold
                // for a faster carrier instead.
                if (oversize || item.class == QueueClass::Bulk)
                    && profile.cost == CostClass::Airtime
                {
                    held_for_airtime = true;
                    continue;
                }
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
                if let Ok(fragments) = send_via(transport.as_ref(), hint, &item.envelope).await {
                    if let Some(bodies) = fragments {
                        self.remember_fragments(item.peer, item.envelope.token, bodies, now);
                    }
                    sent = true;
                    break;
                }
            }

            if sent {
                self.store.queue_ack(seq)?;
                self.backoff.remove(&seq);
                self.held_notified.remove(&seq);
                if let Some(msg_id) = item.msg_id {
                    self.mark_sent(&item.peer, &msg_id, rng)?;
                }
                if let Some(group_msg_id) = item.group_msg_id {
                    self.group_mark_sent(&item.peer, &group_msg_id, rng)?;
                }
            } else if candidates.is_empty() && held_for_airtime {
                // Held, not failed: nothing was attempted, so no backoff —
                // the item goes out on the first tick after a faster
                // carrier reaches the peer. Surface the honest feedback
                // once per message, not per tick.
                if let Some(msg_id) = item.msg_id {
                    if self.held_notified.insert(seq) {
                        self.events
                            .push_back(Event::AwaitingFasterLink { id: msg_id });
                    }
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

    /// Move third-party transit toward its other side (ADR-0009): mesh-heard
    /// envelopes become mailbox deposits at the bridge relays (any
    /// acceptance means the recipient registered that token there — done);
    /// carrier-surfaced (internet-origin) envelopes flood the broadcast
    /// carriers a bounded number of times. Runs after [`Node::flush`], so
    /// the node's own traffic always claims airtime first. Transit failures
    /// are paced with the same backoff as the delivery engine and dropped
    /// at their attempt caps or TTL — the *senders'* end-to-end retries and
    /// receipts remain the source of reliability, never the bridge.
    async fn flush_transit(&mut self, now: u64) {
        let Some(bridge) = &mut self.bridge else {
            return;
        };
        bridge
            .queue
            .retain(|item| now.saturating_sub(item.first_seen) <= TRANSIT_TTL_SECS);
        if bridge.queue.is_empty() {
            bridge.queue_bytes = 0;
            return;
        }
        let relays = bridge.relays.clone();
        let mut queue = std::mem::take(&mut bridge.queue);
        let transports = self.transports.clone();

        let mut mesh_floods = 0usize;
        let mut kept = VecDeque::new();
        for mut item in queue.drain(..) {
            if now < item.next_ok {
                kept.push_back(item);
                continue;
            }
            if item.from_mesh {
                // Mesh → internet: offer the deposit around; the first
                // acceptance hands custody to a store-and-forward hop that
                // recognized the token.
                let mut accepted = false;
                let mut attempted = false;
                'relays: for relay in &relays {
                    for transport in &transports {
                        // Split horizon: transit never returns to the mesh.
                        if transport.profile().cost == CostClass::Airtime {
                            continue;
                        }
                        if transport.reachable(relay).await == Reachability::Unreachable {
                            continue;
                        }
                        attempted = true;
                        if transport.send(relay, &item.envelope).await.is_ok() {
                            accepted = true;
                            break 'relays;
                        }
                    }
                }
                if accepted {
                    continue; // done — drop from the queue
                }
                if !attempted {
                    // No relay was even reachable (none configured yet, or
                    // the internet side is down): held, not failed.
                    item.next_ok = now + RETRY_BASE_SECS;
                    kept.push_back(item);
                    continue;
                }
                let delay =
                    (TRANSIT_DEPOSIT_RETRY_BASE_SECS << item.attempts.min(7)).min(RETRY_CAP_SECS);
                item.attempts += 1;
                if item.attempts >= TRANSIT_DEPOSIT_ATTEMPTS {
                    continue; // no relay ever recognized it — bounded honesty
                }
                item.next_ok = now + delay;
                kept.push_back(item);
            } else {
                // Internet → mesh: flood on the broadcast carriers, paced
                // per tick and re-flooded on a fixed short schedule (no
                // feedback channel exists — receipts are end-to-end).
                if mesh_floods >= TRANSIT_MESH_PER_TICK {
                    kept.push_back(item);
                    continue;
                }
                let mut flooded = false;
                for transport in &transports {
                    let Some(hint) = transport.broadcast_hint() else {
                        continue;
                    };
                    // Fragment bodies are not retained: the bridge cannot
                    // serve NACKs for traffic it cannot read.
                    if send_via(transport.as_ref(), &hint, &item.envelope)
                        .await
                        .is_ok()
                    {
                        flooded = true;
                    }
                }
                if flooded {
                    mesh_floods += 1;
                    item.attempts += 1;
                    if item.attempts >= TRANSIT_MESH_FLOODS {
                        continue; // flood budget spent — drop
                    }
                    item.next_ok = now + (TRANSIT_REFLOOD_BASE_SECS << item.attempts.min(7));
                } else {
                    // No broadcast carrier took it (airtime exhausted, radio
                    // gone): try again shortly, without spending a flood.
                    item.next_ok = now + RETRY_BASE_SECS;
                }
                kept.push_back(item);
            }
        }

        let bridge = self.bridge.as_mut().expect("bridge unchanged during flush");
        bridge.queue_bytes = kept
            .iter()
            .map(|i| ENVELOPE_HEADER_LEN + i.envelope.body.len())
            .sum();
        bridge.queue = kept;
    }

    /// Remember a just-sent envelope's fragment bodies so an inbound NACK
    /// can retransmit exactly the missing indices. Bounded two ways:
    /// entries expire with the receiver's reassembly window, and beyond
    /// [`MAX_FRAG_CACHE`] messages the oldest is evicted first.
    fn remember_fragments(
        &mut self,
        peer: [u8; 32],
        token: [u8; 32],
        bodies: Vec<Vec<u8>>,
        now: u64,
    ) {
        let Some(id) = bodies
            .first()
            .and_then(|b| b.get(..4))
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
        else {
            return;
        };
        self.frag_cache
            .retain(|_, f| now.saturating_sub(f.sent_at) <= REASSEMBLY_WINDOW_SECS);
        while self.frag_cache.len() >= MAX_FRAG_CACHE {
            let oldest = self
                .frag_cache
                .iter()
                .min_by_key(|(_, f)| f.sent_at)
                .map(|(id, _)| *id);
            match oldest {
                Some(oldest) => self.frag_cache.remove(&oldest),
                None => break,
            };
        }
        self.frag_cache.insert(
            id,
            SentFragments {
                peer,
                token,
                bodies,
                sent_at: now,
            },
        );
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
        Ok(decode_hints(&contact.hints))
    }

    /// Delivery hints for a peer, consulting the discovery planes when the
    /// contact record has none. Sealed sender means an inbound handshake
    /// never reveals a return path — for a contact learned that way, the
    /// peer's published DHT bundle is where the reply path comes from.
    /// Freshly discovered hints are persisted on the contact, so the lookup
    /// happens once, not per flush (and failed sends stay gated by the
    /// delivery engine's backoff regardless).
    async fn resolve_hints(
        &mut self,
        peer: &[u8; 32],
        now: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<DeliveryHint>> {
        let hints = self.hints_for(peer)?;
        if !hints.is_empty() || self.discoveries.is_empty() {
            return Ok(hints);
        }
        let Some(mut contact) = self.store.get_contact(peer)? else {
            return Ok(hints);
        };
        let Ok(identity) = postcard::from_bytes::<IdentityPublic>(&contact.identity) else {
            return Ok(hints);
        };
        let Some(bundle) = self.lookup_bundle(identity.address_digest(), now).await else {
            return Ok(hints);
        };
        let found = decode_hints(&bundle.relay_hints);
        if !found.is_empty() {
            contact.hints = bundle.relay_hints.clone();
            self.store.put_contact(&contact, rng)?;
        }
        Ok(found)
    }
}

/// Hand one envelope to a transport, fragmenting if it exceeds the link MTU.
/// Returns the fragment bodies when fragmentation happened, so the caller
/// can retain them for selective retransmission.
async fn send_via(
    transport: &dyn Transport,
    hint: &DeliveryHint,
    envelope: &Envelope,
) -> Result<Option<Vec<Vec<u8>>>> {
    let mtu = transport.profile().mtu;
    let encoded = envelope.encode();
    if encoded.len() <= mtu {
        transport.send(hint, envelope).await?;
        return Ok(None);
    }
    // Fragments never nest (the receiver treats nested ones as malformed):
    // a retransmitted fragment that does not fit this link makes the
    // scheduler fall through to a wider one, it is never split again.
    if envelope.kind == EnvelopeKind::Fragment {
        return Err(NodeError::Protocol(
            kult_protocol::ProtocolError::MtuTooSmall,
        ));
    }
    let budget = mtu
        .checked_sub(ENVELOPE_HEADER_LEN)
        .ok_or(NodeError::Protocol(
            kult_protocol::ProtocolError::MtuTooSmall,
        ))?;
    let bodies = fragment(&encoded, budget)?;
    for body in &bodies {
        transport
            .send(
                hint,
                &Envelope::new(EnvelopeKind::Fragment, envelope.token, body.clone()),
            )
            .await?;
    }
    Ok(Some(bodies))
}

/// Flush priority (docs/05-transports.md §4.2 rule 3): text > receipts >
/// prekey/handshake. Fragments rank with text — a retransmitted piece
/// completes a message the mesh has already mostly paid for. Group text is
/// text; group control ranks with receipts (it unlocks reading but carries
/// no user words).
fn flush_class(kind: EnvelopeKind) -> u8 {
    match kind {
        EnvelopeKind::Message | EnvelopeKind::Fragment | EnvelopeKind::GroupMessage => 0,
        EnvelopeKind::Receipt | EnvelopeKind::GroupControl => 1,
        EnvelopeKind::Handshake => 2,
    }
}

fn scheduled_info(record: ScheduledMessageRecord) -> ScheduledMessageInfo {
    let conversation = match record.conversation {
        StoreScheduledConversation::Peer(peer) => ScheduledConversation::Peer(peer),
        StoreScheduledConversation::Group(group) => ScheduledConversation::Group(group),
    };
    ScheduledMessageInfo {
        id: record.id,
        conversation,
        created_at: record.created_at,
        not_before: record.not_before,
        body: record.body,
    }
}

fn encode_hints(hints: &[DeliveryHint]) -> Vec<Vec<u8>> {
    hints
        .iter()
        .map(|h| postcard::to_allocvec(h).expect("hint serialization cannot fail"))
        .collect()
}

/// Decode persisted/published hint blobs, skipping any that fail to parse
/// (hints are routing data — a bad entry costs a delivery path, never
/// correctness; the bundle signature already guarantees the blobs are the
/// owner's, not what they contain).
fn decode_hints(blobs: &[Vec<u8>]) -> Vec<DeliveryHint> {
    blobs
        .iter()
        .filter_map(|bytes| postcard::from_bytes(bytes).ok())
        .collect()
}
