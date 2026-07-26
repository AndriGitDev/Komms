# ADR-0033: Nonprofit founder stewardship

- **Status**: Accepted
- **Date**: 2026-07-26

## Context

Komms is being built as public-benefit communications infrastructure rather
than as a venture-backed service or a data business. During the construction
and stabilization phase, Andri is the sole maintainer and directs a broad,
tool-assisted implementation program. Contributions and criticism are welcome,
but a governance structure should reflect the community that actually exists
rather than simulate plural ownership before adoption.

The software is licensed under AGPL-3.0-only. The project's nonprofit mission,
the license's reciprocal source obligations, independent assurance, and product
authority are related but distinct:

- a mission governs official project conduct;
- a copyright license governs downstream permissions and obligations;
- an independent review supplies evidence; and
- the founder remains accountable for product and release decisions unless
  authority is explicitly delegated.

## Decision

### 1. Official Komms activity has a nonprofit public-benefit mission

The project and any service it operates or designates as an official default
exist to make private, resilient communication broadly accessible. Official
activity does not sell user data, attention, access to surveillance, or
preferential protocol control.

Donations, grants, sponsorship, paid work, and cost recovery may fund
infrastructure, accessibility, security review, maintenance, development, and
reasonable compensation. Surplus is reinvested in that mission rather than
distributed as private profit. Until an appropriate legal entity exists, this
is a project governance commitment, not a claim that Komms is a registered
charity, tax-exempt entity, or legally incorporated nonprofit.

### 2. Founder direction is the intentional incubation model

The founder holds final product, protocol, merge, release, delegation, and
roadmap authority during construction and stabilization. Automated research and
implementation systems are tools, not maintainers, reviewers, copyright holders
represented by the project, or decision-makers. The human maintainer remains
accountable for provenance, scope, testing, acceptance, and public claims.

External reviewers may publish findings and decline to support an assurance
claim. Their work is evidence, not shared product governance or an automatic
transfer of release authority. Unresolved findings remain visible and cannot be
described as closed, audited, or independently approved.

### 3. Community governance follows a real community

Anyone may contribute code, design, testing, research, translation, operations,
or criticism now. Maintainer authority is delegated explicitly after sustained,
dependable participation. No contributor count, reviewer count, or calendar date
automatically transfers founder authority.

When adoption has produced a durable community of users, contributors,
reviewers, and operators, the founder may propose additional maintainers, a
foundation, a steering body, or another accountable structure. Any transfer is
public, explicit, proportionate to the community that exists, and preserves the
nonprofit public-benefit mission.

### 4. AGPL provides reciprocity, not an ethical-use prohibition

AGPL-3.0-only permits use by individuals, companies, governments, and paid
operators. When AGPL section 13 applies, an operator of a modified covered
version that supports remote network interaction must prominently offer the
interacting users that version's Corresponding Source.

This is deliberately stronger reciprocity than a permissive license, but it
does not:

- prohibit surveillance, government, or commercial use;
- guarantee that every modification is published to the general public;
- prove that a deployed binary matches offered source;
- automatically cover separate interoperating software; or
- replace enforcement, trademark policy, reproducible builds, signed releases,
  protocol verification, or user choice.

Official Komms services follow the nonprofit mission. Independent operators
retain every right the AGPL grants, including commercial use, and are not
official merely because they run compatible software.

### 5. Official infrastructure remains replaceable

A project-operated bootstrap, discovery, mailbox, rendezvous, relay, wake, or
update service is a default operator, never a protocol authority. Its source,
deployment policy, retention behavior, funding, and material incidents are
public. Users may replace or remove it, and loss of every optional service
leaves the server-independent core intact.

## Alternatives considered

### Form a committee before adoption

Rejected. It creates titles without a sustained contributor base and obscures
who is actually accountable for the product.

### Treat external reviewers as product governors

Rejected. Independent reviewers must be free to report findings without
becoming responsible for roadmap or release decisions.

### Add a noncommercial or government-use prohibition

Rejected. It would conflict with open-source freedom and would not provide a
reliable technical barrier against hostile use. Komms instead uses reciprocal
source obligations, a protected official identity, verifiable protocol rules,
and replaceable infrastructure.

### Promise that AGPL prevents surveillance forks

Rejected as an overclaim. AGPL can expose qualifying modified source to remote
users; it cannot make hostile behavior impossible or prove what binary an
operator deployed.

## Consequences

- Founder-led development is documented as intentional rather than disguised as
  plural governance.
- Independent security and interoperability evidence remains a stable-release
  requirement without granting product authority.
- Official services can accept mission-aligned funding and pay reasonable costs
  or compensation without becoming profit-distribution vehicles.
- Commercial and government use remain legally possible under AGPL.
- A future legal entity, trademark policy, funding policy, and copyright/asset
  inventory must implement this decision without narrowing downstream AGPL
  rights.
