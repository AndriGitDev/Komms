# Komms stabilization program

**Status:** active  
**Scope:** Alpha to a trustworthy stable release and protocol wire v1  
**Accountable owner:** lead maintainer until ownership is delegated in
[MAINTAINERS.md](../MAINTAINERS.md)

Komms should feel like an everyday messenger while strong privacy, user-owned
identity, and resilient fallbacks stay underneath. This program freezes that
product direction and turns the remaining trust gaps into release gates.

It is the canonical source for stabilization priority. The
[engineering roadmap](08-roadmap.md) and
[feature delivery plan](12-feature-delivery-plan.md) remain useful inventories,
but a completion label there does not override a gate here.

Founder-directed implementation may continue throughout stabilization.
Implementation authorship is not independent evidence. Stabilization freezes
what qualifies for a stable release; it does not prevent
isolated roadmap work needed to make Komms broadly capable, reliable,
accessible, and polished. Experimental breadth must not silently expand the
stable-v1 profile or block closure of its trust gates.

## 1. Product and architecture contract

The stabilization work must preserve these boundaries:

1. **Everyday messaging comes first.** Installation, pairing, sending, receiving,
   recovery, and honest delivery state must be understandable without knowing
   transport or cryptography terminology.
2. **There is no mandatory exclusive provider.** The pure core can be operated
   without an optional project service. Standard mode may include replaceable,
   clearly disclosed defaults to make first use practical; users can replace or
   remove them.
3. **Optional services cannot read message plaintext or hold user Komms
   identity private keys.** Runtime service identities, TLS keys, or provider
   credentials are separately scoped and disclosed. Removing rendezvous or
   native wake may reduce convenience, but it must not change the message
   format, user identity, or cryptographic trust root.
4. **DHT first contact and durable store-and-forward mailboxes remain core
   protocol roles.** Bootstrap peers and mailbox operators may be chosen or
   self-hosted. Current Alpha provider configuration and mailbox persistence
   still require qualification.
5. **Post-pairing rendezvous and content-free native wake remain optional.**
   They may improve mobile reachability after a relationship exists, as proposed
   in ADR-0017 through ADR-0019, but are not prerequisites for pure-core
   communication.
6. **No mode may silently weaken a guarantee.** Standard, Private, or Sovereign
   presentation may change defaults and convenience, not message
   confidentiality, identity ownership, or the meaning of delivery receipts.
7. **Official operation serves a nonprofit public-benefit mission.**
   Project-operated or officially designated default services use revenue and
   capacity to sustain access, infrastructure, security, accessibility,
   maintenance, and development. Independent AGPL operators may operate
   commercially and are not represented as official unless they accept the
   applicable service and trademark policy. See
   [ADR-0033](adr/0033-nonprofit-founder-stewardship.md).

## 2. Evidence vocabulary

Public status claims use the strongest level actually demonstrated:

| Level | Meaning |
|---|---|
| **Designed** | A reviewable requirement, threat boundary, or ADR exists. |
| **Implemented** | The relevant production path exists in the repository. |
| **Automated evidence** | Repeatable tests exercise the claimed path and are recorded in CI or a release evidence bundle. |
| **Field-qualified** | Named physical devices, operating systems, radios, and real network conditions pass a recorded matrix. |
| **Independently interoperable** | A separately produced implementation or external test fixture exchanges the normative format successfully. |
| **Independently reviewed** | A qualified person outside the implementation authorship has reviewed the scoped design or code and published a disposition. |
| **Stable** | The applicable P0 gates are closed, compatibility is declared, support and update paths exist, and the release evidence is published. |

These levels are not interchangeable. A simulator build is automated evidence,
not device qualification. A self-round-trip test is not independent
interoperability. Use **available in Alpha** for a feature users can exercise in
an Alpha package. Do not use unqualified **shipped**, **complete**, **audited**,
or **production-ready** as substitutes for evidence.

Each gate closes with links to durable evidence: tests and logs tied to a
revision, a signed review report, a field matrix, a decision record, or a
published release artifact. Screenshots and assertions without revision or
environment details are supporting material, not closure.

## 3. Accountability and evidence roles

| Code | Owner category | Responsibility |
|---|---|---|
| **FND** | Founder / lead maintainer | Product boundary, priority, final release accountability, delegation |
| **SEC** | Core security | Cryptography, identity, storage, threat model, abuse resistance |
| **NET** | Network and services | Discovery, NAT traversal, mailbox durability, radio, operator behavior |
| **PROD** | Product and clients | Onboarding, ordinary messaging, accessibility, localization, recovery |
| **REL** | Release engineering | Builds, signing, updates, provenance, reproducibility, evidence archive |
| **COM** | Community and governance | Contribution path, conduct, review coverage, transparent decisions |
| **LEG** | Legal and brand | Name-risk assessment, trademarks, licensing boundaries, policy wording |
| **EXT** | Independent evidence providers | External security review, interoperability, field, or accessibility evidence; no product, merge, or release authority unless separately delegated |

One person may temporarily fill several categories, but evidence is not
independent when author and reviewer are the same person. The founder remains
accountable for unassigned gates and must identify the actual individual next
to each gate before work begins.

## 4. P0 — trust and release blockers

Every applicable P0 gate must close before a stable release. P0-02 requires a
documented brand-risk decision, not an automatic rename. As of 2026-07-26,
[komms.app](https://komms.app/) uses “Komms Protocol” for a different
communication-infrastructure project. That observation is a monitoring input,
not a legal conclusion or engineering veto. Work continues while the founder
records a proportionate keep, adjust, or rename decision before stable brand
and wire identifiers are frozen.

The current founder decision is to continue using Komms with monthly
monitoring; the limits and escalation triggers are in the
[name-risk decision](32-name-risk-decision.md). The frozen scope is the
[stable-v1 product profile](30-stable-v1-product-profile.md), and every P0 gate
and stable claim is tracked in the
[release evidence ledger](31-release-evidence-ledger.md).

| Gate | Owner | Required evidence | Unlocks |
|---|---|---|---|
| **P0-01 Honest claims and evidence ledger** | FND + SEC + PROD | Public pages use the vocabulary above; security, deletion, blocking, legal-policy, platform, and feature-status claims cite their limits and evidence. A release-scoped ledger links every stable claim to a revision and artifact. | Stable marketing and release notes |
| **P0-02 Name-risk assessment and recorded decision** | LEG + FND | A dated search records relevant marks, categories, jurisdictions, domains, package identifiers, observed confusion, and migration cost. The founder records a keep, adjust, or rename decision and monitoring cadence; qualified trademark advice is used when actual confusion, enforcement contact, or expansion makes it proportionate. | Stable naming and long-lived identifiers |
| **P0-03 Stabilized core product profile** | FND + PROD + SEC | A frozen v1 profile covers install, contact establishment, pairwise text, groups at a stated bound, attachments at stated limits, backup/recovery, blocking, and honest delivery. Additional roadmap work remains isolated from the stable profile until its applicable evidence closes. | Coherent beta scope |
| **P0-04 Clean-install and real-network golden path** | NET + PROD + EXT | On fresh supported devices, two users on distinct ordinary NATs can install, establish first contact, exchange messages, go offline, and receive later without editing addresses or configuration. Standard defaults are disclosed and replaceable; default blackhole, alternate-bootstrap, replacement-operator, and pure-core/self-hosted journeys are exercised separately. | Credible everyday internet use |
| **P0-05 Unsolicited-contact abuse admission** | SEC + NET + PROD + EXT | Before a first payload creates durable contact/session state or consumes scarce prekeys, the accepted contact gate, bounded proof-of-work or equivalent cost, rate limits, block controls, storage quotas, and recovery behavior pass adversarial and usability tests. | Safe public discovery |
| **P0-06 Independent crypto and protocol assurance** | SEC + EXT | Normative external vectors cover PQXDH, Double Ratchet state transitions, sealed envelopes, downgrade behavior, backup/recovery, and malformed inputs; an independent reviewer publishes scope, findings, fixes, and residual risks. Self-tests remain useful but are labelled accordingly. | Stable security claims |
| **P0-07 Signed and recoverable distribution** | REL + SEC + EXT | Production-signed supported artifacts, protected release keys, provenance/SBOM, reproducible-build measurements, verified install/upgrade/rollback, and an authenticated update or clearly bounded manual-update path are exercised from a clean device. | Stable binary distribution |
| **P0-08 Durable mailbox and operator qualification** | NET + SEC + EXT | Mailbox ciphertext survives restart/crash within declared retention and quota rules; expiry, deletion hints, overload, abuse, upgrade, backup, observability, and multi-operator failure behavior are tested. RAM-only discovery/rendezvous nodes do not count as mailbox-durability evidence. A maintained self-hosting path identifies costs and responsibilities. | Trustworthy asynchronous delivery |
| **P0-09 Field qualification across supported claims** | PROD + NET + REL + EXT | A published matrix covers named Android and iOS devices, desktop systems, background/lock lifecycle, NAT classes, network handoff, accessibility, recovery, and the two-radio hardware bench. Unsupported combinations are stated instead of inferred from simulator or CI results. | Supported-platform declaration |
| **P0-10 Accountable founder authority, review, and incidents** | FND + COM + SEC | Founder authority, delegation, code ownership, conduct and recusal, security intake, incident handling, release accountability, and succession are public. Independent review requirements are assurance gates rather than transfers of product authority; missing evidence is reported instead of implied. | Trustworthy release authority |

Work in the stabilization branch toward P0-05 includes a canonical 128 KiB
envelope limit, an explicit accept/refuse contract on `/komms/envelope/2`, and a
direct inbox bounded to 256 items and 8 MiB. The encrypted deferred inbox is
also capped at 2,048 rows / 64 MiB and suppresses exact multipath duplicates.
Global libp2p connection counts, fragment/NACK work, courier bundles, directory
ingress, and mailbox-v1 page/token/lifecycle work now have explicit interim
bounds; large mailbox and token lists rotate without front-of-list starvation.
These paths have local automated tests, but the evidence is not yet tied to a
published revision or independently reviewed, so P0-05 remains open. They bound
carrier and disk surfaces but do not by themselves provide pre-acknowledgement
first-contact admission, identity blocking, or mailbox abuse controls.

## 5. P1 — adoption and ecosystem readiness

P1 work follows a coherent P0 beta and should not delay corrections to P0
claims or safety.

| Gate | Owner | Required evidence | Outcome |
|---|---|---|---|
| **P1-01 Fast contributor path** | COM + REL | A newcomer can build one target, run a bounded required test set, find a suitable issue, and submit a focused change without completing the entire release matrix. Maintainer-only publication remains protected. | Sustainable contribution funnel |
| **P1-02 Localization and accessibility system** | PROD + COM + EXT | User-facing strings leave source code, at least one non-English locale exercises every shell, bidi/Unicode and pluralization tests run, and an external accessibility pass records findings. | Reach beyond early technical adopters |
| **P1-03 Stand-alone protocol and conformance kit** | SEC + NET + EXT | Versioned wire/state specifications, fixtures, compatibility policy, reference traces, and an independently run conformance suite exist outside implementation prose. | Credible third-party implementations |
| **P1-04 Operator program and sustainable capacity** | NET + COM + FND | A dedicated service image and runbook, version/support policy, resource model, abuse response, telemetry boundary, and funding assumptions are tested with at least two independently operated nodes. | Replaceable, plural infrastructure |
| **P1-05 License, trademark, and asset policy** | LEG + COM | AGPL-3.0-only scope, section-13 source-offer obligations, commercial-use rights, contribution terms, documentation/specification/artwork licenses, trademark use, package names, and third-party assets are documented without implying that the nonprofit mission narrows downstream AGPL rights. | Safe reuse without brand confusion |
| **P1-06 Nonprofit funding and transparency** | FND + COM | Official project and service income, expenditure, infrastructure cost, surplus use, conflicts, paid work, and sponsor independence are reported on a predictable cadence. | Mission-aligned durability |
| **P1-07 Privacy, legal, and incident runbooks** | SEC + LEG + COM | Data-flow inventory covers cloud/provider visibility, optional-service retention, lawful requests, service-key compromise, cross-role correlation, advisory publication, and user notification; the response paths are rehearsed. | Operational trust under pressure |

## 6. P2 — expansion outside the stable profile

The founder may research or implement P2 work during Alpha when it is isolated
from the stable profile. It is not enabled or represented as stable until the
everyday messenger and the feature's own evidence are proven:

- live video, very large groups, advanced moderation, and high-bandwidth media;
- additional delay-tolerant networks such as Freenet-style carriers;
- cross-protocol federation or standards participation beyond the P1
  conformance work;
- richer optional discovery/wake services, provided the boundaries in section 1
  remain intact;
- governance evolution considered by the founder after sustained adoption has
  created a real community able to carry delegated responsibility.

Each P2 proposal needs a user problem, privacy impact, operational cost,
compatibility plan, and evidence budget. Feature count is not a stability
signal.

## 7. First 90 days

### Days 0–30: reset the trust surface

- Freeze the stable-v1 contract and name accountable people for every P0 gate;
  keep broader roadmap work isolated so it cannot silently expand that contract.
- Correct public claims and publish the first evidence ledger.
- Record an initial name-risk search, monitoring cadence, and founder
  keep/adjust/rename decision; do not halt engineering solely because another
  project uses a similar name.
- Scope an independent cryptography/protocol review and external vectors.
- Decide first-contact abuse admission and the stabilized v1 product profile.
- Specify the clean-install Standard and pure-core acceptance journeys.
- Publish release signing/update/reproducibility and mailbox-durability plans.

### Days 31–60: make the golden path testable

- Exercise clean installs with replaceable Standard defaults and separately with
  pure-core/self-hosted configuration.
- Land and adversarially test first-contact admission before enabling broad
  public discovery.
- Qualify persistent mailbox restart, retention, quotas, and operator failure.
- Exercise production signing, upgrade/rollback, and evidence capture.
- Extract localizable strings and open a bounded newcomer contribution path.

### Days 61–90: prove it outside the author’s machine

- Run the named-device, real-NAT, background-lifecycle, accessibility, recovery,
  and physical-radio matrix.
- Begin independent review, publish findings and dispositions, and add external
  interoperability fixtures.
- Reproduce release artifacts in a second controlled environment.
- Run a small, consent-based pilot with explicit Alpha limitations and
  measurable install-to-delivery success.
- Publish the gate ledger: closed, open, owner, evidence, and next review date.

## 8. Audit-finding crosswalk

This table prevents a prior concern from disappearing into roadmap prose.

| Finding | Gate |
|---|---|
| Intentional founder-led construction creates continuity and independent-assurance gaps until external evidence and recovery stewardship exist | P0-06, P0-10 |
| Potential similar-name overlap, including komms.app, requires monitoring and a documented founder risk decision; it is not by itself a legal conclusion or automatic rename requirement | P0-02, P1-05 |
| Feature breadth presented ahead of audit, distribution, field qualification, and stable core profile | P0-01, P0-03, P0-09 |
| Fresh installs have no practical internet bootstrap/mailbox defaults; hybrid reachability is design-only | P0-04 |
| ADR-0030 now confines a valid first payload to bounded provisional state with explicit consent; independent adversarial, physical-device, accessibility, discovery, and mailbox-operator qualification remain open | P0-05 |
| Unsigned/debug packages, no updater, incomplete reproducibility and store distribution | P0-07 |
| Absolute blocking, erasure, cryptographic-audit, and current-law wording exceeds demonstrated guarantees | P0-01, P0-06, P1-07 |
| Mailbox state and the operator path are not yet qualified as durable production infrastructure | P0-08, P1-04 |
| Simulator/CI evidence is described beside unresolved device, NAT, radio, background, and accessibility work | P0-01, P0-09 |
| Localization is claimed without a shared localization system or cross-shell locale evidence | P1-02 |
| Contribution rules require release-scale validation and maintainer authorization for ordinary work | P1-01 |
| AGPL reciprocity and the nonprofit mission are clear, but software/documentation/artwork scope, trademark use, contribution rights, and exact section-13 obligations still need a policy | P0-02, P1-05 |
| No durable nonprofit funding, plural-operator, incident, or transparency program is established | P1-04, P1-06, P1-07 |
| No stand-alone conformance suite or independent implementation yet supports a durable ecosystem claim | P0-06, P1-03 |
| Video, large groups, new carriers, federation, and governance expansion could distract from everyday reliability | P0-03, P2 |
| Direct transport now holds its fixed response until exact durable admission/consumption and refuses invalid, duplicate, or over-budget introductions; independent network/adversarial qualification remains open | P0-05 |
| Stable identity-derived DHT locators and public route hints permit polling and network-location correlation | P0-04, P0-05, P0-06 |
| Typed atomic plans and restart injection now cover root-free profile bootstrap/migration, pairwise, group, attachment, scheduled activation, bounded maintenance, ADR-0026 device authority/link/sync/contact projection, and ADR-0030 stage/accept/discard/sweep; the quarantined pre-C2 alias bridge, leased relay custody, and independent/power-loss evidence remain open in the recorded inventory | P0-03, P0-06 |
| Mailbox collection deletes relay custody before the endpoint durably stages and acknowledges a leased page | P0-04, P0-08 |
| Unix store writer exclusion now combines a no-follow sidecar with an owner-only no-follow lock file derived from the database device and inode; equivalent alias resistance and hostile-filesystem qualification remain open on other supported platforms | P0-06, P0-09 |
| The Unix RPC sidecar is no-follow and owner-only, but portable stale-socket replacement still requires a daemon-owned parent directory to exclude hostile rename/unlink races | P0-07, P0-09 |
| ADR-0026 offline-root migration/reset, strict-majority manifests, recovery epochs and root-free `KKR9` are implemented with local crash/cross-shell/simulator evidence; revision-bound CI, physical-device, independent interoperability and independent security evidence remain open | P0-03, P0-06, P0-09 |
| ADR-0027 removes sensitive plaintext SQLite equality identifiers and binds every sealed row, but independent storage review and real macOS, Windows, mobile, power-loss, backup-exclusion, and forensic qualification remain open | P0-03, P0-06, P0-09 |
| ADR-0029 recipient-authenticated group origins are implemented across content, state, sync, RPC/UniFFI and shells with malicious-member, replay/reorder, rotation, restore, shared-mesh and crash evidence; revision-bound CI, independent cryptographic/interoperability review, and physical qualification remain open | P0-03, P0-06, P0-09 |
| ADR-0030 bounded first-contact admission is implemented across signed bundles, pre-KEM proof checks, direct settlement, sealed provisional storage, explicit Accept/Delete/Block and group-invite consent, RPC/UniFFI and all shells with local crash/flood/replay/simulator evidence; independent adversarial/usability review, physical battery/background/accessibility runs, mailbox-v2 operator evidence, and capability-scoped discovery remain open | P0-03, P0-05, P0-06, P0-09 |
| RAM-only storage, disabled logs, and aggregate metrics reduce retention but remain deployment controls; a cloud operator can still observe network metadata, running memory, and availability | P0-01, P0-04, P1-07 |

Until the relevant gates close, Komms is an ambitious public Alpha with
implemented and automated evidence in many areas—not an audited stable
messenger. That distinction protects users and gives contributors a concrete
path to earning stronger claims.
