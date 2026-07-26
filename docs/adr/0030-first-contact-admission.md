# ADR-0030: Bounded first-contact admission and consent

- **Status**: Proposed
- **Date**: 2026-07-26

## Context

A Komms address intentionally lets somebody obtain a signed prekey bundle and
calculate its introduction delivery token. The current receive path performs
Ed25519, X25519, ML-KEM, storage, and session work for that first contact and
then creates a normal contact automatically. The documentation instead
promises a request inbox, proof-of-work, blocking, and optional reputation
inputs.

Open discovery without an admission boundary lets strangers spend endpoint
CPU, battery, memory, one-time prekeys, disk, notifications, and operator relay
capacity. Decentralization removes a mandatory moderator; it does not remove
the recipient's consent boundary.

Admission must work through direct internet, mailbox, mesh, and delayed file
delivery. It must be cheap to reject before expensive cryptography where
possible, bounded after decryption, local-first, and invisible during an
ordinary accepted invitation flow.

## Decision

### 1. The signed bundle advertises a target-specific admission policy

Every public prekey bundle contains a signed, expiring admission descriptor:

- descriptor version and bundle digest;
- validity epoch and maximum clock-skew window;
- recipient-selected puzzle profile and difficulty;
- maximum first-message ciphertext size;
- optional invitation capability commitment; and
- supported anonymous admission-token issuers, if any.

The default public profile requires a bounded SHA-256 client puzzle tied to the
recipient account, exact bundle digest, validity epoch, introduction envelope
content id, and random nonce. Verification is constant-memory and occurs before
ML-KEM decapsulation. Difficulty changes only in a newly signed descriptor;
relays and senders cannot raise it for the recipient.

An authenticated, time-bounded invitation capability conveyed by QR/link/file
may replace the public puzzle. It is single-recipient, rate-bounded, and reveals
no contact petname or future session material. Ordinary invite onboarding
therefore feels immediate while unsolicited public-address contact pays the
admission cost.

IP cookies and subnet limits may protect a direct listener, but they are
defense in depth: they cannot be the protocol admission rule because mailboxes,
carrier NATs, Tor, mesh, and sneakernet do not preserve a useful source IP.

### 2. Resource budgets precede expensive work

Every carrier enforces the canonical envelope byte limit. The node additionally
has fixed global budgets for concurrent introduction verification, puzzle work,
KEM work, provisional rows, total provisional bytes, notification rate, and
per-tick admission time. Mailboxes and bridges have independent byte/item/rate
budgets and never promise acceptance after a quota refusal.

For an interactive carrier, a next-hop `accepted` response is sent only after
the node has either consumed the envelope successfully or transactionally
staged it in the bounded durable admission inbox. A transport-level RAM queue
may prefilter bytes and apply backpressure, but it is not the final acceptance
boundary. The carrier therefore hands the candidate and a response channel to
the node, or writes it to an authenticated durable spool the node owns; it does
not acknowledge an unknown token and discover the durable quota later.

Syntactically invalid, expired, under-difficulty, oversized, duplicate, or
over-budget introductions are rejected before KEM work and never become
pending generic envelopes. Failure responses have bounded uniform shapes and
do not reveal whether a target has free request-inbox capacity.

### 3. A valid stranger becomes a provisional request, not a contact

After a proof passes, the node processes the hybrid handshake into candidate
state and decrypts only the bounded request preview. In one atomic store
transition it:

- consumes the exact one-time prekey, if used;
- seals a provisional session isolated from normal send/group APIs;
- records the verified account/device identity and safety number;
- stores the request id, arrival time, transport class, and bounded preview;
  and
- inserts one sealed request-inbox row.

It does not create a trusted contact, expose normal history, advertise
capabilities, accept group membership, start media, send a delivery receipt, or
make the provisional session available to unrelated content.

The request inbox is fixed-count and fixed-byte. One identity may hold at most
one live request; a replacement follows deterministic newest-valid rules
without increasing capacity. Expiry removes provisional keys and content.

### 4. Accept, reject, block, and invite are explicit state transitions

Accept atomically promotes the provisional identity/session, creates the local
contact petname, stores the first message in normal history, and sends the
encrypted acceptance/delivery result. The user can verify the safety number
before or after acceptance under the existing trust states.

Reject deletes provisional state and creates only a short bounded replay
tombstone. Block creates a sealed local rule keyed by the exact account/device
identity and rotates public invitation capability material where required.
Blocking also removes wake/rendezvous capability, queued copies, group invites,
and provisional state without claiming remote deletion.

Group invitations use the same consent model. Receipt of an authenticated
invite never silently adds a user to a group, exposes its membership, downloads
media, or creates mesh airtime before acceptance.

### 5. Safety tools remain local and user-controlled

Mute, delete, block, and evidence export are available without a project
account. Evidence export is an explicit local action that warns the user it
reveals selected plaintext and cryptographic context to whoever receives it.

Clients may subscribe to signed block/reputation lists with provenance, expiry,
scope, and an inspectable local decision. Lists never form a hidden global ban
service, never revoke an identity, and never prevent a user from overriding a
non-local recommendation.

### 6. Everyday UI hides admission mechanics

An invitation opens as “Connect with …” and normally bypasses visible puzzle
work. An unsolicited valid introduction appears as a familiar **Message
request** with Accept, Delete, and Block. Technical network, proof, and provider
details stay in diagnostics.

When the endpoint is busy, the sender sees an honest generic retry state rather
than a claim that the recipient read or rejected the request.

## Alternatives considered

### Automatically trust every valid cryptographic handshake

Rejected. Cryptographic identity proves who controls a key; it does not express
the recipient's consent or grant unlimited endpoint resources.

### Rely only on IP/subnet rate limits

Rejected. They punish carrier NATs and Tor exits, are absent on delayed
carriers, and are cheap to distribute around.

### Require a central CAPTCHA or account reputation service

Rejected. It creates a first-contact authority, accessibility and censorship
failure, and a global social-graph observation point.

### Perform KEM first so the puzzle policy can remain private

Rejected. It gives attackers the expensive operation the admission layer is
supposed to protect. Policy privacy is less valuable than endpoint safety.

### Silently drop all unknown senders

Rejected. Public reachability is useful, and everyday users understand a
bounded message-request inbox.

## Consequences

- First contact becomes a separate provisional state machine and storage
  domain.
- Public bundles and handshake/envelope versions change before stable wire v1.
- Invitations provide the fast consumer path; public unsolicited contact pays
  adjustable anti-abuse cost.
- Proof-of-work raises attacker cost but cannot defeat a large distributed
  adversary, so hard resource quotas remain mandatory.
- Acceptance, rejection, blocking, group-invite consent, prekey exhaustion,
  flood, Sybil, battery, disk-full, replay, and delayed-carrier cases become
  release tests.
