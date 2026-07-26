# Release evidence ledger

**Ledger date:** 2026-07-26

**Release scope:** stable-v1 candidate

**Current evidence baseline:** [`main@4fda544`](https://github.com/AndriGitDev/Komms/tree/4fda544739c0665b6a324256d858c16c1d73d992)

**Baseline automated run:** [`a02b064`, CI run 197](https://github.com/AndriGitDev/Komms/actions/runs/30199264838);
this successful PR-head tree is the tree merged by PR #77

**Release-control run:** [`25daa69`, CI run 199](https://github.com/AndriGitDev/Komms/actions/runs/30202463092);
all nine jobs passed on draft PR #78

**Accountable release owner:** Andri (`@AndriGitDev`)

**Stable release decision:** not authorized; all P0 gates remain open

**Next ledger review:** 2026-08-09

This is the canonical release-scoped ledger required by P0-01. It records
evidence; it does not turn a design, test, or founder review into independent
assurance. Links to repository tests identify the current evidence source.
Closure requires retained run output tied to an exact revision and environment,
plus every named external artifact.

Andri temporarily owns founder and internal project categories. Every
independent role is explicitly **Unassigned** until a named external person
accepts it and the assignment is recorded in
[MAINTAINERS.md](../MAINTAINERS.md).

## 1. P0 gate ledger

| Gate | Accountable owner | Current control evidence | Status and open gaps | Revision / artifacts | Next review |
|---|---|---|---|---|---|
| **P0-01 Honest claims and evidence ledger** | Andri (FND; interim SEC/PROD) | Designed: vocabulary, frozen claim register, and this ledger exist; the repository documentation check passed in release-control CI. | **Open.** External website and repository-description corrections remain; no stable release evidence bundle exists. | [Stabilization vocabulary](29-stabilization-program.md#2-evidence-vocabulary); [stable-v1 profile](30-stable-v1-product-profile.md); [CI run 199](https://github.com/AndriGitDev/Komms/actions/runs/30202463092); this ledger; [public-copy follow-up](#4-public-copy-audit) | 2026-08-09 |
| **P0-02 Name-risk assessment and recorded decision** | Andri (FND and project risk owner); qualified trademark counsel: **Unassigned** | Designed: dated founder decision, observed overlap, migration cost, cadence, and escalation triggers recorded. | **Open.** This is not legal clearance. No qualified similarity/class/jurisdiction opinion or trademark/asset policy exists. | [Name-risk decision](32-name-risk-decision.md); [brand system](28-brand-system.md) | 2026-10-26, or trigger event |
| **P0-03 Stabilized core product profile** | Andri (FND; interim PROD/SEC) | Designed: product boundary, bounds, supported-system rule, services, and exclusions frozen. | **Open.** ADR-0026 through ADR-0032 remain proposed; atomic paths beyond ordinary pairwise receive remain incomplete; profile has not passed field or independent review. | [Stable-v1 profile](30-stable-v1-product-profile.md); [P0 ADR index](adr/README.md) | 2026-08-09 |
| **P0-04 Clean-install and real-network golden path** | Andri (interim NET/PROD); independent field evaluator: **Unassigned** | Implemented with local/CI evidence for internet components and shells. | **Open.** No qualified default bootstrap/mailbox, clean-device distinct-NAT matrix, default-blackhole journey, replacement operator, or pure-core journey. | [Internet tests](../crates/kult-node/tests/internet_e2e.rs); [Alpha guide](27-alpha-testing.md); [ADR-0034](adr/0034-operator-minimized-reference-discovery.md) | 2026-08-09 |
| **P0-05 Unsolicited-contact abuse admission** | Andri (interim SEC/NET/PROD); independent adversarial/usability evaluator: **Unassigned** | Designed, with automated evidence for interim byte/count bounds. | **Open.** No pre-KEM admission, durable request inbox, consent promotion, identity block implementation, or adversarial/field evidence. Current first contact can create normal contact state. | [ADR-0030](adr/0030-first-contact-admission.md); [transport bounds](05-transports.md); [protocol tests](../crates/kult-protocol/tests/protocol.rs) | 2026-08-09 |
| **P0-06 Independent crypto and protocol assurance** | Andri (interim SEC); independent cryptography reviewer: **Unassigned**; independent interoperability implementer: **Unassigned** | Automated evidence for local KATs, properties, sessions, and protocol decoding. | **Open.** No external vectors, separate implementation, review scope, findings report, disposition, or residual-risk statement. P0 protocol/security ADRs remain proposed. | [Baseline CI](https://github.com/AndriGitDev/Komms/actions/runs/30199264838); [Crypto KATs](../crates/kult-crypto/tests/kat.rs); [properties](../crates/kult-crypto/tests/properties.rs); [session tests](../crates/kult-crypto/tests/session.rs); [cryptography spec](04-cryptography.md) | 2026-08-09 |
| **P0-07 Signed and recoverable distribution** | Andri (interim REL/SEC); independent release evaluator: **Unassigned** | Implemented Alpha packaging with checksums; some workflow provenance/SBOM paths exist. | **Open.** Stable desktop/mobile signing, protected release-key recovery, authenticated updates, reproducibility measurements, clean install/upgrade/rollback, store/repository publication, and external verification are missing. | [Release runbook](25-release-runbook.md); [release workflow](../.github/workflows/release.yml); [0.3 Alpha artifacts](https://github.com/AndriGitDev/Komms/releases/tag/v0.3.0) | 2026-08-09 |
| **P0-08 Durable mailbox and operator qualification** | Andri (interim NET/SEC); independent operator evaluator: **Unassigned** | Implemented Alpha mailbox-v1 behavior with automated bounds and end-to-end receipt tests. | **Open.** Mailbox v1 can delete before endpoint custody. Persistent v2 deposits, leases, restart/disk-full/overload/expiry/multi-operator evidence, published operator policy, and maintained self-hosting cost model are missing. | [ADR-0032](adr/0032-leased-mailbox-delivery.md); [node mailbox tests](../crates/kult-node/tests/mailbox_e2e.rs); [transport mailbox tests](../crates/kult-transport/tests/mailbox.rs) | 2026-08-09 |
| **P0-09 Field qualification across supported claims** | Andri (interim PROD/NET/REL); independent accessibility/field evaluator: **Unassigned** | Implemented shells and automated host, simulator, and packaging evidence. | **Open.** No published named-device/OS/NAT/background/handoff/accessibility/recovery/two-radio matrix. macOS and Linux stable support cells are not frozen. | [Local release gate](24-local-release-gate.md); [HIL bench](10-hil-bench.md); [candidate platform rule](30-stable-v1-product-profile.md#1-installation-and-supported-systems) | 2026-08-09 |
| **P0-10 Accountable founder authority, review, and incidents** | Andri (FND; interim COM/SEC); independent reviewers and backup steward: **Unassigned** | Implemented as public governance, ownership, security intake, recusal, release authority, and incident policy. | **Open.** No accepted backup steward, independent sensitive-surface reviewers, rehearsed incident record, or continuity handoff. Founder self-review is not independent. | [Governance](../GOVERNANCE.md); [maintainers](../MAINTAINERS.md); [security and incidents](../SECURITY.md); [CODEOWNERS](../.github/CODEOWNERS); [ADR-0033](adr/0033-nonprofit-founder-stewardship.md) | 2026-08-09 |

## 2. Stable public claim register

These are the complete stable public claims authorized by the frozen profile.
The quoted wording is the strongest stable wording permitted after its evidence
closes. Until then, public copy must use the current evidence level and disclose
the listed gap. A new stable claim requires a new identifier here.

| Claim | Stable wording | Owner | Current evidence level | Revision / artifacts | Open gaps | Next review |
|---|---|---|---|---|---|---|
| **SV1-C01 Distribution** | Supported Komms clients install, update, and recover through authenticated release paths. | Andri (REL/SEC); external release evaluator: **Unassigned** | Implemented Alpha packaging only | [0.3 release](https://github.com/AndriGitDev/Komms/releases/tag/v0.3.0); [release runbook](25-release-runbook.md) | P0-07 signing, updates, rollback, reproducibility, and key recovery | 2026-08-09 |
| **SV1-C02 Local identity** | Komms identity can be created without a required phone number, email address, real name, or project account. | Andri (SEC/PROD); external reviewer: **Unassigned** | Automated evidence | [Identity design](06-identity-trust.md); [node e2e](../crates/kult-node/tests/node_e2e.rs); [FFI e2e](../crates/kult-ffi/tests/ffi_e2e.rs) | Independent protocol review and supported-platform clean-install evidence | 2026-08-09 |
| **SV1-C03 Pairwise confidentiality and authenticity** | Accepted contacts exchange authenticated end-to-end encrypted pairwise text; intermediaries receive sealed envelopes rather than message plaintext. | Andri (SEC); external cryptography reviewer: **Unassigned** | Automated evidence | [`main@4fda544`](https://github.com/AndriGitDev/Komms/tree/4fda544739c0665b6a324256d858c16c1d73d992); [KATs](../crates/kult-crypto/tests/kat.rs); [node e2e](../crates/kult-node/tests/node_e2e.rs) | P0-06 external vectors/review/interoperability; remaining atomic transitions under ADR-0028 | 2026-08-09 |
| **SV1-C04 Contact establishment** | Intentional Connect codes and bounded message requests establish contact without making a project service the identity authority. | Andri (SEC/NET/PROD); external evaluators: **Unassigned** | Designed | [ADR-0030](adr/0030-first-contact-admission.md); [ADR-0031](adr/0031-capability-scoped-dht-discovery.md) | Implement, accept, adversarially test, and field-qualify v2 contact flow | 2026-08-09 |
| **SV1-C05 Pairwise text bounds and atomicity** | One stable-v1 text event carries at most 65,507 UTF-8 bytes and changes visible/delivery state only through its complete atomic transition. | Andri (SEC/PROD); external reviewer: **Unassigned** | Automated evidence for the bound and one receive slice; full claim designed | [Content codec](../crates/kult-protocol/src/content.rs); [ADR-0028](adr/0028-atomic-protocol-commits.md); [node e2e](../crates/kult-node/tests/node_e2e.rs) | Pairwise send, handshake, receipt, failure injection, and independent review | 2026-08-09 |
| **SV1-C06 Bounded groups** | Stable-v1 groups support at most 64 active accounts and authenticate the claimed sender separately for every recipient. | Andri (SEC/PROD); external reviewer: **Unassigned** | Automated evidence for current bounded groups; required origin property designed | [Group tests](../crates/kult-node/tests/groups_e2e.rs); [ADR-0029](adr/0029-recipient-authenticated-groups.md) | Implement recipient origin, atomic group transitions, upgrade path, malicious-member evidence, and independent review | 2026-08-09 |
| **SV1-C07 Bounded attachments** | Consented attachments use authenticated resumable chunks, a 512 MiB primary limit, a 256 KiB preview limit, and no bulk airtime carrier. | Andri (SEC/PROD/NET); external reviewer and field evaluator: **Unassigned** | Automated evidence | [ADR-0015](adr/0015-encrypted-attachment-pipeline.md); [protocol constants](../crates/kult-protocol/src/attachment.rs); [attachment e2e](../crates/kult-node/tests/attachments_e2e.rs); [media store tests](../crates/kult-store/tests/media.rs) | Accept ADR-0015 or successor; atomic transition coverage; protected-file device matrix; independent review | 2026-08-09 |
| **SV1-C08 Backup and recovery** | A versioned encrypted backup restores eligible user state on a clean supported device while live protocol secrets reset; offline account-root recovery replaces a lost device set. | Andri (SEC/PROD); external reviewer and field evaluator: **Unassigned** | Automated evidence for KKR7 round trips; stable authority designed | [Storage contract](07-storage.md#4-backup--portability); [backup tests](../crates/kult-store/tests/backup.rs); [backup e2e](../crates/kult-node/tests/backup_e2e.rs); [ADR-0026](adr/0026-revocable-device-authority.md) | Offline-root implementation, format freeze, conflict/stolen-device tests, clean-device field matrix, independent review | 2026-08-09 |
| **SV1-C09 Blocking** | Blocking is an exact local identity rule that removes local relationship capabilities and state without claiming remote erasure or global identity revocation. | Andri (SEC/PROD); external abuse/usability evaluator: **Unassigned** | Designed | [ADR-0030](adr/0030-first-contact-admission.md#4-accept-reject-block-and-invite-are-explicit-state-transitions); [profile boundary](30-stable-v1-product-profile.md#7-blocking-and-deletion) | Implement block state/transitions across carriers, groups, capabilities, restore, and supported clients; adversarial/usability evidence | 2026-08-09 |
| **SV1-C10 Honest delivery** | Queued means durable local custody, sent means bounded next-hop custody, and delivered requires an authenticated end-to-end receipt; none means read. | Andri (SEC/NET/PROD); external evaluator: **Unassigned** | Automated evidence for current ladder; stable custody designed | [Architecture lifecycle](03-architecture.md#3-message-lifecycle); [transport semantics](05-transports.md); [node e2e](../crates/kult-node/tests/node_e2e.rs); [ADR-0032](adr/0032-leased-mailbox-delivery.md) | Durable direct admission, mailbox v2, crash matrix, operator and real-network qualification | 2026-08-09 |
| **SV1-C11 Supported platforms** | The stable release supports only the named device, OS, architecture, lifecycle, install, upgrade, and accessibility cells published as passed. | Andri (PROD/REL); independent field/accessibility evaluator: **Unassigned** | Implemented shells with automated build/simulator evidence | [Platform rule](30-stable-v1-product-profile.md#1-installation-and-supported-systems); [release gate](24-local-release-gate.md) | P0-09 named physical matrix and exact macOS/Linux support cells | 2026-08-09 |
| **SV1-C12 Replaceable services** | Standard defaults are disclosed and replaceable; no project service is the user identity authority or receives message plaintext or user identity private keys. | Andri (NET/SEC/FND); external operator reviewer: **Unassigned** | Designed; pure-core components implemented | [Stabilization contract](29-stabilization-program.md#1-product-and-architecture-contract); [ADR-0034](adr/0034-operator-minimized-reference-discovery.md); [self-hosting](26-self-hosting.md) | Dedicated reference services, public configuration/revision, default-blackhole and replacement evidence, independent operator review | 2026-08-09 |
| **SV1-C13 Resilient retry and fallback** | Komms retains queued work, retries within declared bounds, and can use more than one supported route; it does not guarantee availability or delivery time. | Andri (NET/PROD); external field evaluator: **Unassigned** | Automated evidence | [Transport design](05-transports.md); [node delivery tests](../crates/kult-node/tests/node_e2e.rs); [mesh policy tests](../crates/kult-node/tests/mesh_policies.rs); [sneakernet tests](../crates/kult-transport/tests/sneakernet.rs) | Real NAT, background, handoff, operator-failure, and two-radio field matrix | 2026-08-09 |
| **SV1-C14 Local deletion limits** | Delete removes live logical history and Komms-owned references from the current profile; it does not promise forensic or remote erasure. | Andri (SEC/PROD); external storage reviewer: **Unassigned** | Implemented with automated evidence in current schema; inactive v2 destination foundation implemented | [Storage limits](07-storage.md); [ADR-0027](adr/0027-opaque-indexed-store.md); [v2 destination foundation](../crates/kult-store/src/store_v2.rs); [ephemeral tests](../crates/kult-node/tests/ephemeral_e2e.rs) | Complete all-table conversion and atomic replacement, migration/remnant qualification, supported-platform storage review | 2026-08-09 |
| **SV1-C15 Nonprofit project mission** | Official Komms activity follows a nonprofit public-benefit mission; this is project policy, not registered-charity status and not a restriction on independent AGPL commercial use. | Andri (FND/COM; project policy owner); qualified legal reviewer: **Unassigned** | Implemented governance policy | [ADR-0033](adr/0033-nonprofit-founder-stewardship.md); [governance](../GOVERNANCE.md) | Legal entity, funding/trademark/asset policies, and qualified policy review remain P1 work | 2026-10-26 |

## 3. Evidence-level rules

1. A source file or ADR is **Designed**, not proof that runtime behavior occurs.
2. A merged implementation without a repeatable test is **Implemented**.
3. A test file becomes **Automated evidence** only when retained output names
   its exact revision, environment, command, and result.
4. Simulator, emulator, localhost, self-round-trip, or founder-only review does
   not satisfy field, independent interoperability, or independent review.
5. An independent role stays `Unassigned` until the named person has accepted
   the scope and conflict requirements in a public record.
6. A gate closes only through a ledger change that links all required artifacts
   and records founder release disposition. Closing one claim does not close
   another claim or its P0 gate.

## 4. Public-copy audit

### In-repository surfaces

The README, governance/security/contribution files, active product documents,
platform READMEs, and user-visible attachment copy are checked by
`python3 scripts/check-docs.py`. The check validates relative Markdown links,
the complete P0/claim identifiers, and terminology that previously overstated
deletion, source-metadata removal, evidence, or implementation provenance.

Negative statements such as “not independently audited” remain permitted and
necessary. The everyday promise “Private messaging that keeps working.” also
remains; the frozen profile supplies its availability limit.

### Public surfaces outside this repository

These corrections cannot be completed by this repository change and remain
P0-01 follow-up:

| Surface | Observed wording or risk | Required disposition |
|---|---|---|
| [`komms.org`](https://komms.org/) | The indexed page title still says 0.1 while the page presents 0.3. “works anywhere” and “truly deletable” exceed the stable claim register; the AGPL summary also compresses section-13 scope. | Align the version/title. Keep “Private messaging that keeps working.” Replace universal reachability and deletion wording with `SV1-C13` and `SV1-C14`; align the source-offer summary with ADR-0033. |
| [GitHub repository description](https://github.com/AndriGitDev/Komms) | “serverless” and “functional on & off the grid” can read as current universal/field-qualified claims. | Describe an Alpha with direct, local, radio, and file transport implementations and name the outstanding stable/field gates. |
| Release and package listings | Old screenshots, summaries, or package descriptions can outlive repository corrections. | Audit at every release; stable wording must cite a claim id and the release evidence bundle. |

The accountable owner for these external corrections is Andri. Completion must
be linked here before P0-01 closes.
