# Komms stable-beta candidate

This file is a release-note template, not a published release or a stability
claim. Replace every bracketed field with revision-bound evidence before it is
placed in a completed release bundle.

Private messaging that keeps working: Komms uses user-owned identity and
end-to-end encryption for ordinary conversations while disclosed, replaceable
internet services and local, mailbox, mesh, radio, and sneakernet fallbacks
remain underneath.

## Candidate identity

- Version: `[version]`
- Source revision: `[full revision]`
- Artifact manifest SHA-256: `[digest]`
- Evidence bundle SHA-256: `[digest]`
- Offline release-manifest signature: `[verification result and fingerprint]`

## Earned support

List only platform/device/OS rows that passed with the exact candidate
artifacts. Everything else is unsupported, even if it builds or ran in a
simulator.

- `[supported cell and evidence]`

## Security and privacy boundary

Messages are end-to-end encrypted, but endpoint compromise can expose local
plaintext and keys. Optional providers can observe bounded network metadata
and interfere with availability. Mailboxes hold sealed ciphertext under their
declared retention and quota limits. Komms does not promise remote or forensic
erasure, universal availability, guaranteed delivery time, anonymity merely
from sharing a Connect code, or immunity from a device or operator that is
compromised.

Independent security and conformance evidence:

- `[review/report/disposition evidence]`

## Delivery and fallback

Queued means local durable custody. Sent means bounded next-hop custody.
Delivered requires an authenticated end-to-end receipt and does not mean read.
Wake and rendezvous acknowledgements never advance those states.

- Standard defaults and replacement evidence: `[evidence]`
- Private ingress and administrative-domain limits: `[evidence]`
- Sovereign/pure-core and fallback evidence: `[evidence]`

## Pilot and qualification

- Consent-based pilot aggregate: `[evidence; no participant identifiers]`
- Clean install and first contact: `[evidence]`
- Offline delivery and service blackhole: `[evidence]`
- Backup/recovery and linked-device loss: `[evidence]`
- Signed upgrade and rollback: `[evidence]`
- Physical mobile/desktop/accessibility matrix: `[evidence]`
- Physical radio matrix: `[evidence]`

## Known limitations and residual risks

- `[open or explicitly accepted risk, owner, review date, user impact]`

## Support, updates, and rollback

- Support window and contacts: `[evidence]`
- Authenticated-store or bounded-manual update path: `[evidence]`
- Rollback action and tested prior/clean-restore target: `[evidence]`

This candidate does not authorize publication, merge, tagging, store
submission, or a stable claim. Those decisions remain separate and explicit.
