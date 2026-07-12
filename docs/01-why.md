# 01 — Why Komms Exists

## The moment

The EU's "ChatControl" legislation (the CSA Regulation's mandatory-detection provisions)
requires communication services to scan private messages — including, in practice,
end-to-end encrypted ones via client-side scanning. Whatever its stated aims, its
mechanism is the same one every mass-surveillance system uses: a checkpoint between you
and the person you're talking to, operated by someone who is not either of you.

The technical community's assessment has been consistent for decades and was repeated,
loudly, about this bill: **there is no such thing as a scanning mechanism that only works
for the good guys.** A backdoor is a backdoor; a scanner is a wiretap; infrastructure
built for one purpose is repurposed by the next government, the next breach, the next
mission-creep amendment.

Komms's answer is architectural rather than rhetorical: build a messenger with **no
service provider to compel**. You cannot order a checkpoint installed where no
intermediary exists. See [02 — Threat Model](02-threat-model.md), adversary A1.

## The position

- **Private correspondence is a human right.** Article 12 UDHR and Article 8 ECHR were
  written for envelopes; encryption is simply the envelope that works at internet scale.
  A right that evaporates the moment communication is digital was never protected at all.
- **Encryption is math, not a privilege.** It cannot be uninvented and it does not
  distinguish between people a given government likes and people it doesn't. Journalists,
  lawyers, doctors, abuse survivors, activists, and everyone else use the same
  ciphersuites — weakening them for anyone weakens them for everyone.
- **Sovereignty over your data means holding your own keys**, on your own hardware, with
  the ability to walk away — export everything, run every component yourself, read every
  line of code. Trust should be something you *verify*, not something you're asked for.

## Why another messenger?

Signal is excellent — and it is a *service*, with servers, phone-number identity, and a
single operating organization that can be pressured, blocked, or banned from app stores.
Matrix federates but leaks metadata generously and still assumes servers. Briar proved
serverless mesh messaging is possible but stops at the phone's own radios.

The empty niche Komms targets:

1. **Serverless by architecture**, not by promise — DHT + friend relays + mesh, no
   component the project must run ([03 — Architecture](03-architecture.md)).
2. **Off-grid as a first-class transport**, not a demo: commodity Meshtastic LoRa radios
   give kilometers of range and multi-hop store-and-forward when networks are shut down
   or shut off ([05 — Transports](05-transports.md)).
3. **Bleeding-edge cryptography, conservatively assembled**: hybrid post-quantum key
   agreement (X25519 + ML-KEM-768), Double Ratchet with encrypted headers,
   XChaCha20-Poly1305 everywhere, sealed-sender delivery — every construction from the
   published state of the art, no invented primitives
   ([04 — Cryptography](04-cryptography.md)).
4. **No identifiers**: identity is a keypair you mint yourself
   ([06 — Identity & Trust](06-identity-trust.md)).

## Who it's for

Anyone who wants their communications held to a sovereign standard: people organizing
under connectivity shutdowns, professionals with confidentiality duties, communities
building resilient local infrastructure, and ordinary people who think a private
conversation should stay private. Privacy tools only protect their users well when using
them is unremarkable — the goal is software good enough that people choose it on quality,
and the privacy comes with it.

## The commitments

1. Every line of code public, AGPLv3, forkable forever.
2. No servers we run, no accounts, no identifiers, no telemetry. Nothing to subpoena.
3. No custom crypto primitives; published constructions only; external audit before any
   "stable" label ([08 — Roadmap](08-roadmap.md), M6).
4. Honest limits, in writing: what Komms cannot protect against is documented as
   carefully as what it can ([02 — Threat Model §4](02-threat-model.md)).
