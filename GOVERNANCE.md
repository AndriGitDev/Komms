# Komms governance

Komms is founder-led by design during construction and stabilization. Founder
Andri holds final product, technical, merge, release, and delegation authority
while directing implementation toward a stable, polished, broadly capable
messenger. This is not a claim of independent oversight. Governance may evolve
when sustained adoption produces a real community capable of carrying
responsibility; no date, reviewer count, or maintainer count automatically
transfers authority.

Komms has a nonprofit public-benefit mission. The project and every service it
operates or designates as an official default must advance broad access to
private, resilient communication. Revenue or surplus supports infrastructure,
maintenance, security, accessibility, development, and reasonable compensation
rather than private profit distribution. This is a project policy, not a claim
of registered-charity or tax-exempt status, and it does not restrict the AGPL
rights of independent operators, including commercial use. The complete
decision is [ADR-0033](docs/adr/0033-nonprofit-founder-stewardship.md).
The [funding report and cadence](docs/48-funding-transparency.md) implement the
mission without inventing a legal entity or narrowing independent AGPL rights.

## Roles

- **Lead maintainer:** accountable for product direction, delegation, merge and
  release authority, and the integrity of public status claims.
- **Maintainer:** owns a documented area, reviews changes, and helps operate the
  project. Appointment and removal are recorded in
  [MAINTAINERS.md](MAINTAINERS.md).
- **Qualified reviewer:** supplies scoped technical, security,
  interoperability, accessibility, or operational evidence independently of
  the implementation authorship. Review does not grant product-direction,
  merge, release, or veto authority unless the founder separately delegates a
  documented maintainer role.
- **Contributor:** anyone who improves code, documentation, testing, design,
  research, translations, or issue reports under the project contribution
  terms.

Current people and unfilled responsibilities are listed in
[MAINTAINERS.md](MAINTAINERS.md). The lead maintainer is accountable for an
unfilled area until it is explicitly delegated.

## Decisions

Issues and pull requests are the ordinary public decision record. Material
changes to protocol compatibility, cryptography, identity, trust boundaries,
storage formats, optional-service boundaries, or governance require an ADR or a
documented governance proposal before implementation.

Accepted ADRs are normative until superseded by a later ADR. Maintainers should
state the user problem, alternatives, security and privacy consequences,
migration plan, and evidence required for acceptance. Rough consensus is
preferred; the lead maintainer makes the final decision and records the
reason when consensus is not possible.

Implementation method does not change accountability. The human maintainer who
approves a change remains accountable for provenance, scope, review, testing,
acceptance, and public claims. Only evidence meeting the published independence
criteria counts as independent review.

## Review and release

Every accepted change requires accountable approval by an owner for the affected
area. During the single-maintainer Alpha the founder may author and approve a
change, with that lack of independence disclosed. Changes to cryptography,
authentication, identity, wire formats, storage migrations, release signing, or
optional-service trust boundaries require two qualified reviewers, including
one who did not author the change, before a stable release.

While those reviewers do not exist, the project may continue clearly labelled
Alpha research and testing, but it must not describe the affected work as
independently reviewed, audited, or stable. CODEOWNERS routes review requests;
it is not evidence that independent review occurred.

External review substantiates assurance claims; it is not shared product
governance. Reviewers may publish findings and decline to provide a positive
assurance statement. The lead maintainer decides product disposition and
release timing, but unresolved findings remain visible in the evidence ledger
and cannot be represented as closed, audited, or independently approved.

The lead maintainer currently authorizes releases. A stable release also
requires all applicable P0 gates in the
[stabilization program](docs/29-stabilization-program.md) to be closed with
published evidence. The current owners, unassigned independent roles, claim
register, gaps, and review dates are recorded in the
[release evidence ledger](docs/31-release-evidence-ledger.md).

## Conflicts, conduct, and appeals

Maintainers disclose financial, employment, close personal, or competitive
interests that could reasonably affect a decision and recuse themselves where
appropriate. A person whose conduct is being reviewed does not decide that
case. If no unconflicted maintainer is available, the lead maintainer will seek
a mutually acceptable independent reviewer and document the process while
protecting reporters' privacy.

Project participation follows the [Code of Conduct](CODE_OF_CONDUCT.md).
Technical decisions may be appealed with new evidence in the original issue or
through a superseding proposal. Conduct decisions may be appealed privately to
an unconflicted maintainer.

## Security and operator independence

Vulnerabilities follow [SECURITY.md](SECURITY.md), including coordinated
disclosure. No project-operated bootstrap, mailbox, rendezvous, wake, update, or
other service may become the authority for a user's identity or receive message
plaintext or identity private keys. Operational convenience does not override
the architectural boundaries in the stabilization program.

The [operator program](docs/46-operator-program.md) records deployability,
capacity, costs, support, abuse, incidents, and the still-unassigned external
operator slots. The
[license, trademark, and asset policy](docs/47-license-trademark-assets.md)
separates copyright permissions from official project identity.

## Succession and evolution

Release credentials, domains, package identities, and incident procedures
should have documented recovery and at least one authorized backup steward
before a stable release. A temporary steward may maintain security and release
continuity when the lead maintainer cannot act; permanent authority changes
must be publicly recorded.

No backup steward currently exists. The role remains visibly unassigned in
[MAINTAINERS.md](MAINTAINERS.md), and stable release authority remains blocked
until a real person accepts the scope and the credential-recovery procedure is
rehearsed. Repository access or a platform role alone does not confer project
or release authority.

Governance evolution is not automatic. When sustained adoption has produced a
real community of users, contributors, reviewers, and operators, the founder may
publish a proposal for additional delegated maintainers, a foundation, a
steering body, or another accountable structure. Any transfer of authority must
be explicit, public, mission-preserving, and proportionate to the community that
actually exists.
