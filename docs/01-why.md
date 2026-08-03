# 01: Why Komms Exists

## The moment

*Legal-status note, last checked 2026-07-26: this is project motivation, not
legal advice.*

European policy commonly discussed as “Chat Control” is not one already-enacted
law that universally requires private-message scanning. The proposed permanent
Child Sexual Abuse Regulation remains in negotiation between EU institutions.
Separately, on 2026-07-23 the Council gave final approval to a new temporary
measure allowing providers to resume certain voluntary detection activity.
The [Council's current overview](https://www.consilium.europa.eu/en/policies/prevent-child-sexual-abuse-online/)
distinguishes those interim rules from the permanent framework still being
negotiated. This page must be updated when that status changes.

Komms is motivated by the broader and durable risk: proposals or laws that make
private communication scannable create a checkpoint between people who are
talking, operated by someone who is not either of them.

Security experts have repeatedly warned that a privileged scanning mechanism
creates a capability that can be abused, breached, expanded, or repurposed.
Komms therefore treats content confidentiality as a technical boundary rather
than a promise that a scanner will always be used as intended.

Komms's answer is architectural rather than rhetorical: build a messenger with
**no mandatory exclusive content-bearing provider**. DHT first contact and
durable mailbox delivery remain core roles whose operators can be chosen or
self-hosted. Optional post-pairing rendezvous and wake services may be pressured
to log or deny their own work, but they must never receive message plaintext or
identity private keys. Removing them leaves pure-core routes available, although
an adversary may still block every usable route. See
[02: Threat Model](02-threat-model.md), adversaries A1 and A3.

## The position

- **Private correspondence is a human right.** Article 12 UDHR and Article 8 ECHR were
  written for envelopes; encryption is simply the envelope that works at internet scale.
  A right that evaporates the moment communication is digital was never protected at all.
- **Encryption is math, not a privilege.** It cannot be uninvented and it does not
  distinguish between people a given government likes and people it doesn't. Journalists,
  lawyers, doctors, abuse survivors, activists, and everyone else use the same
  ciphersuites; weakening them for anyone weakens them for everyone.
- **Sovereignty over your data means holding your own keys**, on your own hardware, with
  the ability to walk away: export everything, run every component yourself, read every
  line of code. Trust should be something you *verify*, not something you're asked for.

## Why another messenger?

Signal is excellent, and it is a *service*, with servers, phone-number identity, and a
single operating organization that can be pressured, blocked, or banned from app stores.
Matrix federates but leaks metadata generously and still assumes servers. Briar proved
serverless mesh messaging is possible but stops at the phone's own radios.

The empty niche Komms targets:

1. **A server-independent core**, not an exclusive-provider promise: DHT first
   contact + chosen durable mailbox operators + direct/local/mesh paths, with no
   optional project service required to communicate
   ([03: Architecture](03-architecture.md)).
2. **Off-grid as an implemented Beta transport**, not yet a field-qualified
   claim: Komms supports Meshtastic LoRa adapters and bounded multi-hop
   store-and-forward. Actual range, background behavior, and two-radio operation
   remain environment- and hardware-dependent release evidence
   ([05: Transports](05-transports.md)).
3. **Modern cryptographic constructions, conservatively assembled**: hybrid post-quantum key
   agreement (X25519 + ML-KEM-768), Double Ratchet with encrypted headers,
   XChaCha20-Poly1305, and sealed-sender delivery. The primitives and
   constructions are published; their combination in Komms is not yet
   independently audited or independently interoperable
   ([04: Cryptography](04-cryptography.md)).
4. **No mandatory registration identifiers**: identity is a keypair you mint
   yourself, without a required phone number, email address, or real name
   ([06: Identity & Trust](06-identity-trust.md)).

## Who it's for

Anyone who wants their communications held to a sovereign standard: people organizing
under connectivity shutdowns, professionals with confidentiality duties, communities
building resilient local infrastructure, and ordinary people who think a private
conversation should stay private. Privacy tools only protect their users well when using
them is unremarkable: the goal is software good enough that people choose it on quality,
and the privacy comes with it.

## The commitments

1. Project-owned software remains public under AGPL-3.0-only and forkable
   forever. Qualifying modified network versions owe their interacting users a
   Corresponding Source offer; the license does not prohibit government or
   commercial use.
2. No mandatory exclusive service, account, phone number, email, or telemetry.
   Standard mode may use disclosed and replaceable bootstrap or mailbox
   defaults. Optional post-pairing convenience services are public,
   replaceable, content-blind, and honest about the bounded metadata they can be
   compelled to disclose or work they can deny
   ([ADR-0017](adr/0017-optional-hybrid-modes.md)).
3. No custom crypto primitives; published constructions only; external audit before any
   "stable" label ([08: Roadmap](08-roadmap.md), M6).
4. Honest limits, in writing: what Komms cannot protect against is documented as
   carefully as what it can ([02: Threat Model §4](02-threat-model.md)).
5. Official project activity and default services follow a nonprofit
   public-benefit mission. Funding sustains access, infrastructure, security,
   accessibility, maintenance, and development rather than data monetization or
   private profit distribution
   ([ADR-0033](adr/0033-nonprofit-founder-stewardship.md)).
