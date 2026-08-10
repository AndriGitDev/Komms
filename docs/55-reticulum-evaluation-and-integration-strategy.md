# Reticulum evaluation and conditional integration strategy

**Status:** Proposed strategy; pre-ADR; no implementation or release authorization  
**Decision owner:** Andri, founder and lead maintainer  
**Date:** 2026-08-10  
**Applies to:** `AndriGitDev/Komms`

## 1. Executive decision

Komms will evaluate Reticulum as a possible optional carrier. It will integrate Reticulum only if recorded evidence shows a material improvement in resilient connectivity without weakening Komms's security model, stable-v1 product contract, licensing position, platform viability, or provider independence.

A favorable evaluation does **not** authorize replacing the Komms protocol with Reticulum, LXMF, Sideband, or their identity and message formats. The preferred integration boundary is:

> Reticulum may carry already sealed Komms envelopes. Komms remains authoritative for accounts, devices, contact admission, PQXDH and Double Ratchet state, groups, message content, storage, delivery receipts, blocking, backup, recovery, and user-visible truth.

The first eligible integration is an experimental, disabled-by-default carrier for headless and desktop Sovereign-mode deployments. Standard and Private modes retain their existing route restrictions unless a later ADR explicitly proves and authorizes a compatible Reticulum profile. Mobile support, public defaults, LXMF propagation, and stable-v1 inclusion are separate decisions.

The current libp2p, LAN, Meshtastic, mailbox, and courier-file carriers remain supported. Reticulum must be removable without changing a Komms account, contact, conversation, message, backup, or stable wire/state record.

## 2. Why evaluate Reticulum

Reticulum provides mature capabilities that Komms should not reproduce without first testing whether they can be safely reused:

- self-configuring multihop routing across heterogeneous physical and IP links;
- operation over RNode/LoRa, packet radio, serial, Wi-Fi, Ethernet, TCP, UDP, I2P, and custom interfaces;
- efficient path discovery and rebalancing on constrained networks;
- initiator-anonymous packets with no source address in the network header;
- Packet, Link, Channel, Buffer, Request, and Resource mechanisms for different payload and session shapes; and
- an existing operator and application ecosystem.

The evaluation must also address material concerns:

- the official implementation uses the custom Reticulum License, while Komms is AGPL-3.0-only;
- the protocol is public domain, but the reference implementation is authoritative and no independent formal specification is intended;
- public GitHub repositories are mirrors and public support/community management has been withdrawn;
- the reference stack is Python-based, while Komms embeds a Rust runtime on mobile;
- Reticulum and LXMF have not completed an external security audit;
- Reticulum destinations, announces, ratchets, receipts, and propagation behavior create a second identity and routing system that must not become Komms authority; and
- LXMF's signed source/destination message format and store-and-forward semantics do not automatically fit Komms's deniable message, opaque-token, per-device, and delivery-state contracts.

Reticulum therefore enters as prior art and a candidate transport dependency, not as a presumed foundation.

## 3. Non-negotiable Komms boundaries

Every evaluation and implementation must preserve these rules.

### 3.1 Trust and cryptography

1. Komms account and device private keys never enter Reticulum, LXMF, an RNS daemon, an adapter, an interface driver, or an RNode.
2. A Reticulum identity is a rotatable transport credential only. It cannot sign a Komms device certificate, manifest transition, message, group event, recovery, or delivery receipt.
3. Komms performs end-to-end encryption before carrier selection. Reticulum encryption is additive link/transport protection and is never load-bearing for Komms confidentiality, authenticity, forward secrecy, or post-compromise security.
4. Reticulum or LXMF receipt evidence can mean only that an outer hop or destination accepted bytes under its own contract. Only an authenticated Komms end-to-end receipt can produce the user-visible `Delivered` state.
5. A transport failure, malformed announce, path conflict, adapter crash, or dependency downgrade must fail closed and leave the durable Komms queue recoverable.

### 3.2 Identity and metadata

1. No Komms account digest, safety number, contact petname, group id, message id, delivery token, mailbox capability, or device certificate appears in an RNS destination name, announce application data, interface name, log, metric, or public directory.
2. Reticulum route handles are random, scoped, rotatable, sealed at rest, and distributed only through an already authorized Komms relationship or explicit Sovereign-mode configuration.
3. RNS transport private keys are device-local and excluded from portable Komms backups and ordinary owned-device sync. Restore creates fresh transport credentials and rotates the corresponding authorized route hints.
4. Public or community Reticulum entrypoints are never silently enabled. Connectivity bootstrap is explicit, inspectable, replaceable, and removable.
5. Komms does not inherit Reticulum marketing claims. The UI and documentation must not claim anonymity, untraceability, unstoppable delivery, or emergency readiness without Komms-specific evidence.

### 3.3 Architecture and operations

1. The integration implements the existing `Transport` contract and sees ciphertext only.
2. No Reticulum component becomes mandatory for account creation, contact establishment, backup, recovery, ordinary internet delivery, or pure-core operation.
3. Disabling or uninstalling the integration cannot destroy queued ciphertext, history, contacts, or cryptographic session state. The scheduler continues over eligible remaining carriers.
4. All queues, payloads, retries, announces, paths, transfers, reassemblies, logs, and IPC frames are bounded.
5. Transport I/O and user-visible events stay outside database transactions. Existing typed commit plans and post-commit event rules remain authoritative.
6. The integration exposes no generic remote shell, command execution, file transfer, plugin execution, or Reticulum administration surface to peers.
7. Existing Standard, Private, and Sovereign policy remains authoritative. No new direct route is introduced into Standard or Private mode without a superseding ADR and evidence.

## 4. Preconditions and authority

Research, lab testing, and a disposable spike may begin without changing the stable-v1 scope. A production-oriented implementation branch begins only from a synchronized `main` after preceding P0 work is merged and current CI is green.

No Reticulum work closes an existing stable-v1 evidence gap. It must not delay or relabel open physical-device, operator, reproducibility, independent interoperability, or security-review work. Experimental implementation may be proposed in a draft PR, but Andri retains final authority over ADR acceptance, merge, release inclusion, and public claims.

Before any official Reticulum code or package is redistributed with Komms, a recorded license review must resolve:

- compatibility of the Reticulum License with AGPL-3.0-only distribution and Section 13 obligations;
- whether an external user-installed daemon, separately distributed bridge, bundled sidecar, or clean-room protocol implementation changes that result;
- application-store, Linux distribution, container, and commercial/government-use implications;
- notices, source-offer, SBOM, provenance, update, and vulnerability-handling obligations; and
- whether the intended development and test process complies with every applicable upstream term.

Unresolved licensing is a stop condition, not a documentation item to defer until release.

## 5. Evaluation program

The evaluation produces reproducible evidence, not a feature checklist. Pass thresholds must be written before measurements are run so they cannot be chosen after seeing the result.

### Phase E0 — Freeze the evaluation target

Record exact source revisions, release artifacts, hashes, dependency versions, configuration, interface firmware, hardware, OS versions, and network topology. The first reference target should use the normal PyCA/OpenSSL-backed RNS package. The pure-Python cryptographic fallback is excluded from qualification unless it receives its own security review.

Retain copies or immutable references for:

- the official Reticulum implementation and manual;
- Reticulum License and public-domain protocol statements;
- the current mirror/support notice;
- RNode firmware and hardware definitions used in testing;
- LXMF and Sideband versions used only for comparison; and
- every Komms baseline revision and release-evidence entry used in the comparison.

### Phase E1 — Architecture and threat-model analysis

Produce a threat-model delta covering at least:

- route discovery and announce correlation;
- malicious transport nodes and interfaces;
- path poisoning, blackholing, replay, delay, duplication, and reordering;
- announce/path-request floods and CPU, memory, disk, and airtime exhaustion;
- stable versus per-relationship destination correlation;
- local daemon/IPC compromise;
- transport-key theft, rotation, revocation, restore, and stale hints;
- RNS version downgrade and use of unexpected crypto backends;
- cross-carrier loops and amplification;
- metadata visible to RNS peers, interface operators, propagation nodes, IP networks, and radio observers; and
- failure of every configured Reticulum entrypoint or interface.

Compare three route-credential hypotheses without selecting one prematurely:

| Hypothesis | Benefit | Principal risk to measure |
| --- | --- | --- |
| Per-device epoch destination | Bounded announce and state cost | Contacts can correlate the same transport destination |
| Per-relationship destination | Better contact separation | Announce volume, path state, radio airtime, and scalability |
| Capability-derived/rotating destination family | Efficient authorized rotation | Key derivation complexity, rollback, collision, and recovery safety |

Every acceptable design keeps the Komms account identity out of RNS and permits transport-hint rotation without changing the safety number.

### Phase E2 — Independent lab validation

Exercise the unmodified Reticulum reference implementation before building a Komms bridge.

Required topologies:

1. local Ethernet/Wi-Fi only;
2. IP-connected peers across distinct real NATs;
3. two directly connected RNodes on the locally lawful radio profile;
4. a three-node radio topology requiring an intermediate transport node;
5. a mixed radio-to-IP-to-radio path;
6. partition, restart, and later convergence;
7. moving destinations and competing paths;
8. degraded, lossy, duplicated, delayed, and reordered links;
9. an unavailable or maliciously noisy bootstrap/entrypoint; and
10. a fully disconnected recipient, explicitly demonstrating what core RNS does and does not provide without application-level store-and-forward.

Measure:

- successful delivery and false-success rate;
- path discovery and reconvergence time;
- bytes and radio airtime per useful Komms-sized payload;
- packet, Link, Resource, and retransmission overhead;
- duplicate and replay behavior;
- CPU, memory, file growth, and idle/active power;
- queue and transfer bounds under hostile input;
- restart behavior at every transfer phase;
- behavior at regulatory duty-cycle limits; and
- operator effort for initial setup, diagnosis, key rotation, and recovery.

Run representative Komms payload classes: receipt/control frames, the normal padded short-text envelope, maximum pairwise text, group fan-out, attachment manifests, and bounded file chunks. Bulk media must not be allowed onto a low-bandwidth route merely because RNS can technically transfer it.

Results must be compared with the existing libp2p, LAN, and Meshtastic carriers. Reticulum passes the value gate only if it delivers a meaningful capability or maintenance advantage rather than another equivalent route with more complexity.

### Phase E3 — Disposable Komms spike

Build the smallest possible adapter around a frozen RNS version. It must not change stable Komms wire/state formats or enter a release package.

The preferred first spike is process-separated:

```text
kult-node
  -> existing Transport trait
  -> feature-gated Reticulum adapter client
  -> owner-only local IPC
  -> minimal komms-rns bridge
  -> reference RNS shared instance / rnsd
  -> configured Reticulum interfaces
```

This shape isolates Python packaging, crashes, upgrades, and licensing while allowing the official implementation to define interoperability. It is appropriate for headless and desktop evaluation only. It does not solve Android or iOS embedding.

The IPC surface must be versioned and deliberately smaller than the RNS API. It may provide only:

- health, version, crypto-backend, and bounded interface-profile status;
- register, rotate, and remove an opaque local transport route;
- send one bounded sealed envelope with priority, expiry, and idempotency data;
- receive one bounded sealed envelope plus an opaque local route handle;
- report path availability, next-hop/destination acceptance, or terminal carrier failure; and
- shut down and erase explicitly selected transport-only state.

It must not expose arbitrary RNS requests, commands, filesystem paths, Python evaluation, plugins, `rnsh`, `rnx`, `rncp`, or remote-management functionality.

### Phase E4 — Spike failure and privacy tests

Inject failure before and after IPC framing, RNS submission, path discovery, link establishment, Resource transfer, outer acknowledgement, inbound admission, Komms commit, memory replacement, and event delivery.

Prove that:

- a bridge crash cannot lose the already committed Komms outbound envelope;
- retry cannot duplicate message history or advance a ratchet twice;
- no outer receipt can produce `Delivered`;
- no plaintext or Komms long-term key crosses the adapter boundary;
- inbound overflow is rejected before unbounded allocation or durable growth;
- stale transport routes cannot revive a revoked Komms device;
- an RNS transport-key restore or clone cannot impersonate a Komms device;
- disabling Reticulum immediately stops new RNS work while preserving the queue for other carriers; and
- logs and diagnostic bundles remain content-free and do not contain stable account or relationship identifiers.

## 6. Conditional target architecture

This section becomes implementation direction only after the evaluation gates pass.

### 6.1 Carrier role

Reticulum is one candidate in the existing transport scheduler. It may provide direct and multihop reachability over its configured interfaces, but it does not own Komms discovery, admission, sessions, groups, queues, history, or receipts.

The scheduler may duplicate an idempotent sealed envelope over Reticulum and another eligible carrier. Existing Komms message ids and replay protection absorb duplicates. RNS-specific identifiers never become conversation or history keys.

### 6.2 Packetization and fragmentation

Exactly one layer must own fragmentation, retransmission, and reassembly for one carrier transfer:

- use an RNS Packet only when the complete bounded carrier frame fits;
- use an RNS Link/Channel/Resource for larger frames when qualification permits;
- do not wrap the existing Komms small-MTU fragment/NACK protocol inside a second RNS retransmission protocol by default; and
- if Komms-level fragments are unavoidable, document which layer owns timeout, retry, quota, cancellation, and final failure so two retry engines cannot amplify each other.

An RNS path or transfer acknowledgement maps at most to Komms `Sent`. The exact encrypted Komms receipt remains queued and returns over any eligible carrier.

### 6.3 Route publication

RNS announces use a fixed application aspect and either no application data or a fixed-size opaque version/capability field. They contain no nickname, status, Komms address, device name, or stable account material.

The selected destination-scoping model must meet predeclared limits for announce frequency, active destinations, retained paths, rotation overlap, radio airtime, and restore cleanup. Contacts learn route hints only through authenticated Komms state. Unknown RNS senders do not bypass ADR-0030 first-contact admission.

Standard and Private modes must not publish or consume a direct RNS route unless a later mode-specific ADR authorizes it. The first integration profile is therefore manual, opt-in Sovereign mode. A future Standard/Private profile would normally need a mailbox-only or non-direct construction consistent with ADR-0031 rather than a hidden policy exception.

### 6.4 Store-and-forward

Core RNS reachability is not represented as offline durable custody. If the recipient is unavailable, Komms retains its existing queue and fallback behavior.

There are three separately gated options:

1. **Direct/multihop RNS only:** simplest initial carrier; no new offline-storage claim.
2. **Komms mailbox over RNS:** expose the existing bounded, leased, ciphertext-only mailbox protocol through an RNS destination while retaining Komms mailbox semantics and receipts.
3. **LXMF outer carriage:** evaluate later only if its propagation network adds unique value. A Komms envelope would remain opaque payload, and LXMF source signatures, destination fields, transient ids, propagation synchronization, deletion, quotas, and receipts would require a separate threat model and ADR. LXMF signatures could never authorize Komms content.

The initial integration excludes option 3.

### 6.5 State and lifecycle

Reticulum state is separated into:

- sealed Komms-owned route metadata and capability bindings;
- device-local RNS transport private keys;
- bounded adapter compatibility and version state; and
- RNS-owned path/cache/interface state with explicit quotas and cleanup.

Transport private keys and live RNS caches are excluded from Komms backup. Recovery, device revocation, relationship blocking, or route reset removes the relevant bindings, requests bounded adapter cleanup, and distributes fresh authorized hints where appropriate. Failure to clean an external cache is reported honestly; it cannot restore Komms authority.

### 6.6 Platform strategy

1. **Linux headless and desktop:** first implementation target using a separately managed bridge/shared RNS instance.
2. **macOS and Windows desktop:** qualify after process lifecycle, IPC, packaging, updates, and protected key storage pass.
3. **Android:** evaluate whether an app-owned managed process or independent native implementation can satisfy lifecycle, background, packaging, and battery requirements. Sideband's Android support is useful evidence but does not qualify the Komms architecture.
4. **iOS:** treat the inability to run an ordinary Python daemon as a first-class constraint. Do not promise iOS Reticulum support without a viable embedded/native implementation and physical-device evidence.

A desktop/headless-only carrier may ship experimentally if labeled as such. It must not create the impression that the same route exists on every Komms platform.

## 7. ADR and implementation sequence after a favorable evaluation

### Phase I0 — Publish the evaluation record

Commit a revision-bound evaluation report containing raw measurements, topology diagrams, configurations, failures, limitations, license result, threat-model delta, and a recommendation. Update the public comparison material to acknowledge Reticulum, LXMF, and Sideband regardless of the adoption decision.

### Phase I1 — Propose ADR-0036

As of this strategy date, the next available decision number is ADR-0036. It should remain Proposed until implementation and qualification evidence exist. It must define:

- exact adopted scope and explicitly excluded RNS/LXMF features;
- supported RNS revision/profile and upgrade policy;
- process/IPC or native implementation boundary;
- transport identity and destination-scoping rules;
- announce and route-hint format;
- mode eligibility;
- packetization, fragmentation, retries, and quotas;
- delivery-state mapping;
- storage, backup, recovery, block, and revocation behavior;
- licensing and distribution model;
- diagnostics and privacy budget;
- rollback and dependency-removal behavior; and
- conformance, security-review, and field-evidence requirements.

Any later use of LXMF propagation, LXST calls, RNS group destinations, default public entrypoints, or a native Reticulum implementation requires either an explicit extension section with its own gates or another ADR.

### Phase I2 — Implement behind hard gates

Candidate repository structure:

- an AGPL `kult-transport-reticulum` adapter implementing the existing trait;
- a canonical bounded IPC codec and adversarial test corpus;
- a minimal companion bridge whose repository/package placement follows the license decision;
- configuration parsing and typed runtime status;
- scheduler integration with existing priority, expiry, duplicate, and fallback rules; and
- no default feature activation in library, daemon, desktop, or mobile builds.

Configuration must require explicit enablement and identify the exact external instance/profile. There is no automatic connection to a global backbone, community directory, or project-operated entrypoint.

### Phase I3 — Verification

Add:

- canonical IPC and adapter fixtures;
- property and fuzz tests for every inbound frame and route record;
- duplicate, reorder, replay, expiry, quota, and malformed-announce tests;
- failpoint/restart matrices across the adapter and existing commit plans;
- two-node and multihop interoperability tests against the pinned reference implementation;
- mixed-carrier fallback and loop-prevention tests;
- wrong-version and wrong-crypto-backend rejection;
- backup/restore, block, device-revocation, and transport-key-clone tests; and
- assertions that no transport outcome can forge an end-to-end receipt.

CI simulation is not physical evidence. Retained field runs must name hardware, firmware, region, OS, configuration, source revision, topology, and observed result.

### Phase I4 — Experimental rollout

Roll out in this order:

1. developer-only build and lab configurations;
2. opt-in Linux headless/desktop Sovereign mode;
3. named macOS/Windows desktop cells if qualified;
4. opt-in mobile Beta only after each physical platform passes; and
5. stable optional-carrier status only after independent interoperability/security review and the stable evidence ledger permits the claim.

Every stage has a kill switch. A rollback removes the carrier from scheduling but keeps Komms queues and histories intact. No migration changes account or message formats.

## 8. Go/no-go gates

All gates are mandatory for the scope they authorize.

| Gate | Pass condition | Failure outcome |
| --- | --- | --- |
| G0 — Strategic value | Reticulum adds demonstrably broader or more maintainable connectivity than existing carriers | Retain as prior art; do not integrate |
| G1 — Licensing | Recorded distribution/interoperation model preserves Komms's AGPL rights and intended commercial/government freedoms | Stop, use external interoperability only if clearly allowed, or reject |
| G2 — Trust containment | Adapter receives no plaintext/account keys and cannot authorize Komms state | Reject architecture |
| G3 — Mode and metadata | Route publication, bootstrap, and observations fit the selected Komms mode and documented privacy budget | Redesign or restrict to a narrower mode |
| G4 — Correctness and recovery | Loss, duplication, reordering, bridge death, restart, restore, block, and revocation preserve exact Komms consequences | Do not merge |
| G5 — Resource bounds | CPU, memory, disk, transfer, announce, path, and airtime behavior stay within predeclared limits under hostile input | Redesign or reject |
| G6 — Operational reliability | Required physical and real-network topology matrix passes with retained evidence | Experimental only |
| G7 — Platform viability | Every advertised platform has an implementable lifecycle and named physical evidence | Limit claims to passing platforms |
| G8 — Upstream resilience | Versions are pinned, updates are reviewable, and loss of upstream support has a credible disable/fork/reimplementation response | Experimental only or reject |
| G9 — User truth | Setup and delivery states remain understandable without misleading anonymity, delivery, or emergency claims | Do not expose to ordinary users |

Possible final decisions are:

- adopt the official RNS implementation through a separated adapter;
- implement only the public-domain protocol in an independently licensed native component after conformance work;
- retain a developer/experimental carrier without product support; or
- reject integration while keeping Reticulum in the comparison and prior-art record.

The evaluation budget creates no presumption in favor of adoption.

## 9. Principal risks and planned responses

| Risk | Planned response |
| --- | --- |
| Reticulum/AGPL incompatibility | Resolve before redistribution; prefer a separately installed instance for the spike; do not copy Sideband/LXMF code |
| Public upstream/support fragility | Pin exact releases, retain artifacts/evidence, isolate dependency, provide disable path, assess independent implementation only after value is proven |
| Python daemon conflicts with embedded mobile runtime | Start headless/desktop; treat Android/iOS as separate gates; do not create false platform parity |
| Two identity systems confuse authority | Make RNS identity transport-only, device-local, rotatable, non-backed-up, and incapable of Komms authorization |
| Announces leak stable relationship metadata | Compare destination-scoping hypotheses, keep app data opaque, limit publication, and measure correlation/airtime |
| Nested fragmentation and retries amplify traffic | Assign one owner per transfer; use RNS Resource/Channel where appropriate; bound all overlap |
| Outer receipts inflate delivery claims | Map them only to carrier/next-hop evidence; require the existing encrypted Komms receipt for `Delivered` |
| RNS lacks required offline custody | Retain Komms queue/mailboxes; treat mailbox-over-RNS or LXMF propagation as separate work |
| Generic RNS utilities enlarge attack surface | Expose a minimal bridge API and disable remote execution, shell, file, plugin, and admin functionality |
| Protocol drift without a separate normative spec | Maintain versioned interoperability fixtures against the authoritative reference implementation and reject unknown versions |
| New carrier delays stabilization | Keep it outside stable-v1 scope and release gates until existing P0 obligations are closed |

## 10. Required work products

Before experimental merge:

1. Reticulum landscape and feature-overlap report.
2. Revision-bound license and redistribution decision record.
3. Threat-model and metadata-budget delta.
4. Reproducible lab configuration and raw benchmark bundle.
5. Baseline comparison against libp2p, LAN, and Meshtastic.
6. Disposable adapter spike and failure report.
7. Proposed ADR-0036.

Before any user-facing Beta:

8. Versioned IPC/adapter specification and conformance fixtures.
9. Security, fuzz, crash, quota, replay, block, revocation, and recovery evidence.
10. Named physical RNode and real-network qualification matrix.
11. Platform lifecycle and packaging evidence for every claimed system.
12. Operator/configuration runbook, update policy, SBOM, notices, and rollback procedure.
13. Updated release evidence ledger, threat model, transports guide, comparison page, third-party notices, and stable-v1 exclusions.

Before stable optional-carrier status:

14. Independent Reticulum interoperability execution by an actually named external party.
15. Independent security review of the Komms adapter boundary and adopted RNS profile.
16. Field evidence showing that the carrier provides the claimed resilience and can be removed without loss of Komms state.

Unassigned independent roles remain explicitly unassigned until a real person accepts them.

## 11. Initial recommendation

If the evaluation is favorable, pursue this narrow first product:

- opt-in Sovereign-mode Reticulum carrier;
- Linux headless and desktop first;
- official RNS reference implementation accessed through a minimal local bridge, subject to the license decision;
- RNode plus explicitly configured local/IP interfaces;
- random device-local transport identity, never a Komms identity;
- direct and multihop RNS Packet/Link/Resource carriage of sealed Komms envelopes;
- no LXMF, LXST, RNS group destinations, public default backbone, or mobile claim in the first integration;
- existing Komms mailbox, queue, scheduler, receipt, block, recovery, and fallback behavior unchanged; and
- feature flag, visible Experimental label, exact version pin, and immediate rollback path.

This captures Reticulum's strongest demonstrated advantage—heterogeneous autonomous routing—while keeping the integration reversible. Broader adoption is earned one independently evidenced boundary at a time.

## 12. Success definition

Reticulum is a successful Komms integration only if users gain materially better resilient connectivity while every core Komms promise remains true when Reticulum is malicious, unavailable, outdated, uninstalled, or legally undistributable.

If that cannot be demonstrated, the correct result is not a compromised integration. It is a documented rejection and continued independent development of Komms's existing carriers.

## References

### Komms

- [Architecture](03-architecture.md)
- [Transports](05-transports.md)
- [Threat model](02-threat-model.md)
- [Stable-v1 product profile](30-stable-v1-product-profile.md)
- [Release evidence ledger](31-release-evidence-ledger.md)
- [ADR index](adr/README.md)
- [ADR-0010: embedded runtime](adr/0010-ffi-embedded-runtime.md)
- [ADR-0025: optional Freenet carrier](adr/0025-optional-freenet-carrier.md)

### Reticulum ecosystem

- [Reticulum repository and authoritative protocol statement](https://github.com/markqvist/Reticulum)
- [Reticulum manual](https://markqvist.github.io/Reticulum/manual/)
- [Reticulum API reference](https://markqvist.github.io/Reticulum/manual/reference.html)
- [Reticulum License](https://github.com/markqvist/Reticulum/blob/master/LICENSE)
- [Reticulum public mirror and support notice](https://github.com/markqvist/Reticulum/blob/master/MIRROR.md)
- [LXMF](https://github.com/markqvist/LXMF)
- [Sideband](https://github.com/markqvist/Sideband)
- [Sideband license](https://github.com/markqvist/Sideband/blob/main/LICENSE)
