# 47: License, Trademark, and Asset Policy

This policy explains repository copyright scope, AGPL obligations, contribution
terms, names, package identifiers, and third-party material. It is project
policy and an inventory, not legal advice, trademark clearance, or a substitute
for advice about a particular deployment or jurisdiction.

## 1. Copyright license scope

Unless a path carries a more specific notice, project-authored material in this
repository is licensed under **GNU AGPL-3.0-only**:

- Rust, Kotlin, Swift, JavaScript, shell, Python, configuration, and build code;
- protocol specifications, ADRs, runbooks, user and contributor documentation;
- project-authored fixtures, diagrams, localization catalogs, and examples; and
- project-authored application icons, screenshots, and artwork.

The root [`LICENSE`](../LICENSE) is the controlling license text. “Only” means
version 3, not “version 3 or any later version.” A third-party notice controls
the identified material instead of this default. Dependency licenses continue
to govern their own packages.

Copyright permission for a logo or screenshot does not grant ownership of the
Komms name, promise endorsement, or remove the trademark rules below.

## 2. AGPL section 13, accurately bounded

When someone modifies the covered Program and that modified version supports
remote interaction through a computer network,
[AGPL section 13](https://www.gnu.org/licenses/agpl.html#section13) requires
that version to prominently offer all remote users an opportunity to receive
its Corresponding Source, from a network server at no charge through a
standard or customary copying method. Corresponding Source is the
license-defined source needed for that covered version, not merely a patch
against Komms. The
[GNU licence FAQ](https://www.gnu.org/licenses/gpl-faq.html#UnreleasedModsAGPL)
provides explanatory guidance; the licence text controls.

Other AGPL obligations can apply when copies are conveyed. The exact license,
not this summary, determines a particular obligation.

The license does **not**:

- require every private modification to be published to the general public;
- automatically cover a separate program merely because it interoperates;
- prove that offered source matches a running binary;
- prohibit commercial, government, surveillance, or other fields of use;
- turn the nonprofit public-benefit mission into an ethical-use restriction;
  or
- make an independent operator an official Komms service.

An operator may charge for copies, hosting, support, or operation while
respecting the license. Official project conduct follows
[ADR-0033](adr/0033-nonprofit-founder-stewardship.md); independent licensees
retain the commercial and government-use permissions the AGPL grants.

A network service record must publish the exact source revision and a
prominent source location for any covered deployed version. The operator
remains responsible for deciding, with qualified advice where proportionate,
whether its modifications and combined works are covered.

## 3. Contributions

Komms uses no contributor licence agreement. A contributor submits only work
they have the right to contribute and agrees that accepted project-authored
material is distributed under the applicable repository license above. The
contributor keeps their copyright; no copyright assignment is implied.

Contributors must:

- identify copied, generated, employer-owned, or third-party material;
- preserve copyright, patent, and licence notices;
- record provenance and license for new assets, fixtures, word lists, fonts,
  icons, and media;
- avoid material whose terms are unknown or incompatible; and
- disclose an employer or other right-holder constraint before acceptance.

Dependency lockfiles and generated SBOM/license reports are inventories, not
blanket legal approvals.

## 4. Trademark and naming policy

The current founder decision is to continue using **Komms** while monitoring
the exact-name overlap described in the
[dated name-risk decision](32-name-risk-decision.md). No registered-mark,
exclusive-right, registrability, non-infringement, or legal-clearance claim is
made here.

Without separate permission, truthful descriptive use is allowed:

- state that software implements or is compatible with the Komms protocol;
- link to the project, quote short names in discussion, and report bugs;
- describe a modified source tree as a fork of Komms; and
- reproduce marks as technically necessary in unmodified screenshots or
  historical attribution.

Those uses must not imply project operation, security review, endorsement, or
release authenticity. Modified products and independent services should use a
distinct primary name, visual identity, application identifier, package
origin, service domain, and signing identity. “Official Komms,” “Komms
Foundation,” “Komms Security,” and confusingly similar default-service or
download branding require explicit founder authorization until a later
trademark steward is appointed.

An independent operator may truthfully say “Komms-compatible mailbox operated
by Example.” It may not say “official Komms mailbox” merely because it uses
AGPL code or passes a conformance test. Compatibility is not endorsement.

The K mark and project logo may be used to link to or identify the unmodified
project. A fork, commercial service, app-store listing, merchandise, domain, or
fundraising campaign should not use the mark as its own brand without written
permission. This policy does not limit uses that applicable law permits
independently.

## 5. Package and service identifiers

The current project identifiers are:

| Surface | Identifier |
|---|---|
| Desktop, Android, iOS | `is.andri.komms` |
| Endpoint container | `ghcr.io/andrigitdev/komms-kultd` |
| Reference-service container | `ghcr.io/andrigitdev/komms-reference-service` |
| Mailbox-v2 container | `ghcr.io/andrigitdev/komms-mailbox` |
| Wake container | `ghcr.io/andrigitdev/komms-wake` |
| OHTTP-relay container | `ghcr.io/andrigitdev/komms-ohttp-relay` |

Only artifacts published through the protected maintainer release process may
use those origins as an authenticity claim. A third-party build changes its
application/package identifier and signing identity unless it is explicitly
designated as an official distribution. Cryptographic domain-separation strings
and wire identifiers are compatibility constants, not branding instructions;
a rename requires a protocol migration rather than a blind replacement.

## 6. Asset and third-party inventory

The machine-readable inventory is
[`operations/v1/assets.json`](../operations/v1/assets.json). It groups the
project logo, generated application icons, and interface screenshots and marks
their stable provenance attestation open.

The repository embeds one known third-party data asset: the verbatim BIP-39
English word list in `crates/kult-crypto/src/wordlist.rs`. BIP-39 identifies the
material as MIT-licensed; the retained notice names Pavol Rusnak as copyright
holder and is
[`LICENSES/BIP-39-MIT.txt`](../LICENSES/BIP-39-MIT.txt). It must not be
described as public-domain data.

Rust and Android dependency evidence is generated by the release controls and
retains exact locked versions and declared upstream expressions. Native Apple
code currently links only platform frameworks and the project FFI library.
Before a stable release, the founder must attest the logo/icon/screenshot
provenance and a qualified licensing reviewer must disposition the inventory.

## 7. Monitoring and review

Run the name-monitoring cadence and triggers in the 2026-07-26 decision. Seek
qualified trademark advice before a stable brand freeze, app-store or paid
expansion, material fundraising, official operator licensing, or when an
actual confusion/enforcement trigger occurs.

The qualified licensing and trademark reviewer remains **Unassigned**.
Generated or founder-authored policy is not an independent legal review.
