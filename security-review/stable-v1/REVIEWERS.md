# Qualified-reviewer research shortlist

**Research date:** 2026-07-31

**Status:** research only. No candidate has been contacted, selected, assigned,
or authorized to begin work. Availability, conflicts, exact team, scope,
schedule, publication terms, and cost are unknown.

The shortlist is deliberately small and unranked. It uses current first-party
service descriptions and public reports to establish plausible relevance, not
to endorse a firm or predict the quality of a future engagement.

## NCC Group Cryptography Services

Why it merits diligence:

- NCC describes a dedicated cryptographic-services practice reviewing
  primitives and security protocols.
- Its public Matrix Olm review covered a deniable Double Ratchet, group
  ratchet, prekey identity binding, replay, fuzzing, findings, remediation, and
  follow-up review.
- Its 2024 XMTP report covers a Rust secure-messaging implementation built on
  MLS.
- Its public `opaque-ke` assessment covers a Rust cryptographic protocol
  implementation; other public work covers encrypted backups and offline key
  recovery.

First-party evidence:

- [Cryptographic Services](https://www.nccgroup.com/penetration-testing-services/)
- [Matrix Olm cryptographic review](https://www.nccgroup.com/media/5bspr3ie/_ncc_group_olm_cryptogrpahic_review_2016_11_01-1.pdf)
- [XMTP MLS implementation review](https://www.nccgroup.com/research/public-report-xmtp-mls-implementation-review/)
- [`opaque-ke` Rust implementation review](https://www.nccgroup.com/research/public-report-whatsapp-opaque-ke-cryptographic-implementation-review/)
- [End-to-end encrypted backups review](https://www.nccgroup.com/research/public-report-whatsapp-end-to-end-encrypted-backups-security-assessment/)
- [Keyfork implementation review](https://www.nccgroup.com/research-blog/public-report-keyfork-implementation-review/)

Questions before selection:

- Which named practitioners with current PQXDH/Double Ratchet, Rust, storage,
  and messaging experience would perform the work?
- Can the team cover the full cross-layer scope rather than only primitive
  cryptography?
- Will the engagement include a public initial/final disposition and reserved
  retest?

## Trail of Bits

Why it merits diligence:

- Trail of Bits describes protocol, implementation, post-quantum, end-to-end
  encryption, and Rust cryptography assessment capability.
- Its published methodology explicitly connects threat models,
  specification/cryptanalysis, implementation review, constant-time and
  serialization risks, malformed/replay testing, fuzzing, reporting, and fix
  review.
- Its public library includes an assessment of the SimpleX secure-messaging
  design/implementation and a ZeroTier protocol-design assessment.

First-party evidence:

- [Cryptography practice and methodology](https://trailofbits.com/services/cryptography/)
- [Software-assurance review and fix-review process](https://trailofbits.com/services/software-assurance/)
- [SimpleX Chat review](https://github.com/trailofbits/publications/blob/master/reviews/SimpleXChat.pdf)
- [ZeroTier protocol review](https://github.com/trailofbits/publications/blob/master/reviews/ZeroTierProtocol.pdf)

Questions before selection:

- Which named practitioners would cover secure messaging, Rust, state/persistence,
  and service abuse bounds?
- Does the proposed team have direct ML-KEM/PQXDH composition experience?
- Are the requested complete public finding/disposition and retest artifacts
  acceptable?

## Least Authority

Why it merits diligence:

- Least Authority describes source-code, specification/white-paper, advanced
  cryptographic-protocol, and decentralized-system architecture reviews.
- It publicly states that its team can review Rust and that its normal process
  includes finding review, verification, and an optional published final
  report.
- Its stated privacy and open-source focus is relevant to the project's
  operator-minimized and public-review goals.

First-party evidence:

- [Security consulting services and process](https://leastauthority.com/security-consulting/)
- [Cryptographic expertise](https://leastauthority.com/security-consulting/cryptographic-expertise/)
- [Security consulting FAQ](https://leastauthority.com/security-consulting/security-consulting-faqs/)
- [Published audits](https://leastauthority.com/security-consulting/published-audits/)

Questions before selection:

- Which named practitioners have non-blockchain secure-messaging, Rust,
  ratchet, and local-store experience?
- Can one engagement cover the complete endpoint/storage/transport scope at
  sufficient depth?
- Will the initial and final report, every finding disposition, and retest be
  public?

## Cure53

Why it merits diligence:

- Cure53 describes white-box code, architecture, infrastructure/platform, and
  cryptographic audits with continuing remediation communication.
- Its public work includes cryptographic-library review, end-to-end encrypted
  storage architecture, VPN/protocol work, and Android/iOS cryptography/client
  assessment.
- Public reports generally identify work packages, team, effort, findings,
  severity, and correction state.

First-party evidence:

- [Services and public reports](https://cure53.de/)
- [Noble cryptography libraries audit](https://cure53.de/audit-report_noble-crypto-libs.pdf)
- [Peergos encrypted storage/design review](https://cure53.de/pentest-report_peergos.pdf)
- [Tangem Android/iOS SDK and cryptography review](https://cure53.de/summary-report_tangem-crypto.pdf)

Questions before selection:

- Which named practitioners would cover PQXDH/Double Ratchet, Rust, durable
  state, and protocol/parser review?
- Can Cure53 allocate a cryptographer and systems reviewers for the full
  package rather than a narrower client penetration test?
- Will the report preserve every finding and retest disposition under the
  proposed public-disclosure terms?

## Selection diligence still required

Before any contact or commitment, record:

1. founder authorization to issue the RFP;
2. the exact package revision and digest;
3. desired timing and an approved budget range;
4. candidate-specific conflict and relationship checks;
5. named practitioner CVs and actual allocation;
6. full-scope coverage and explicit exclusions;
7. source/data handling and deletion terms;
8. ownership and publication rights for report and test artifacts;
9. coordinated-disclosure and retest terms; and
10. whether grant or public-interest funding changes independence,
    publication, scheduling, or credit.

A declined, unavailable, unaffordable, conflicted, or narrow-scope candidate
stays a research record; it is not evidence that review occurred.
