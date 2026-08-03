# Komms name-risk decision

**Decision:** continue using **Komms** for now

**Decision owner:** Andri, founder and lead maintainer

**Assessment date:** 2026-07-26

**Next scheduled review:** 2026-10-26

**Status:** project risk decision; **not legal clearance, a registrability
opinion, or a finding of non-infringement**

## 1. Decision

The project continues using the Komms name while monitoring the exact-name
overlap described below. Engineering and Beta testing continue. Long-lived
stable brand identifiers are not treated as legally cleared, and this decision
does not claim ownership over the word.

The current response is proportionate because:

- the project is still Beta, founder-run, nonprofit in mission, and not
  represented as stable;
- a rename is still possible but already has meaningful package, domain,
  release, artwork, documentation, and wire-domain cost;
- the observed `komms.app` project is a real and close category overlap, but
  this record contains no evidence of actual user confusion, an enforcement
  contact, or a registry opinion; and
- monitoring plus explicit escalation triggers preserve the option to obtain
  qualified advice before expansion or a harder-to-reverse brand freeze.

## 2. Search scope and observations

This founder review used public web, domain, company, package, and official
registry entry points on 2026-07-26. It is a screening record, not a
professional clearance search. Search-engine absence is not evidence that a
right does not exist, and company names, domains, package names, and trademarks
are not interchangeable.

### Closest observed overlap

| Observation | Category proximity | Likely confusion surfaces | Limits of this observation |
|---|---|---|---|
| [`komms.app`](https://komms.app/) presents **“Komms Protocol”** as communication infrastructure using Kaspa, Hippius, and Bittensor, with a waitlist, specifications, privacy page, and a referenced application. | High. Both use the exact word `Komms`, the phrase `Komms Protocol`, cryptography/decentralization language, and communication software. The architectures and visual identities differ. | Search results; verbal recommendations; social handles; press; package/app-store searches; GitHub repository references; phrases such as “Komms protocol,” “Komms app,” and “Komms docs.” | The page establishes public use, not priority, ownership, trademark registration, market reach, or legal rights. |
| [`komms.app/privacy`](https://komms.app/privacy) references `Komms-protocol/komms-core` as a public contact channel. | High for developer discovery and repository attribution. | GitHub search, issue reports, dependency/security notices, protocol discussions, and copied documentation links. | Repository availability, maintainership, legal ownership, and current activity require separate verification. |
| [A KOMMS LTD](https://find-and-update.company-information.service.gov.uk/company/12464746) is an active UK company whose filed activity includes telecommunications. | Medium category proximity, low identity evidence. | Company and provider searches in the UK. | A company registration is not a trademark record and the public filing does not establish a competing software mark. |
| Warframe uses “Komms” for a game resource, including in an [official update](https://www.warframe.com/en/patch-notes/switch/30-0-0). | Low product proximity. | General web search noise and social handles. | Entertainment use is materially different from a private messenger, but no legal conclusion follows. |

No actual confusion report is recorded as of the assessment date.

### Jurisdictions and search categories

The project begins in Iceland and publishes globally through GitHub and public
package surfaces. Monitoring therefore covers at least:

- Iceland, using the
  [Icelandic Intellectual Property Office trademark search](https://www.hugverk.is/en/search/trademark);
- European Union registers and classification tools through
  [EUIPO](https://www.euipo.europa.eu/en);
- international/Madrid records through the
  [WIPO Global Brand Database](https://www.wipo.int/en/web/global-brand-database)
  and [Madrid Monitor](https://www3.wipo.int/madrid/monitor/en/);
- the United Kingdom because of the observed telecommunications company and
  likely software distribution; and
- any jurisdiction targeted by an app-store launch, paid promotion, operator
  contract, grant, or sustained user adoption.

Screening terms include `Komms`, `Komms Protocol`, close visual/phonetic
variants, and the K mark. Product categories include downloadable messaging
software, mobile/desktop applications, telecommunications and message
delivery, hosted software/infrastructure, cryptographic/security software, and
developer protocol services. Nice classes 9, 38, and 42 are useful starting
points for monitoring, not a founder determination of the correct filing
classes.

No qualified person has completed a registry similarity search, common-law/use
search, goods/services comparison, priority analysis, or registrability
opinion for Iceland, the EU, UK, US, or Madrid designations. Those items remain
open.

## 3. Current identifiers and migration cost

The repository currently contains the Komms name in about 200 tracked files.
The cost is not limited to replacing visible prose:

| Surface | Current examples | Migration consequence |
|---|---|---|
| Public identity | `komms.org`, `AndriGitDev/Komms`, Komms logo/screenshots, release names | Redirects, repository/package continuity, documentation and screenshot replacement, search-result ambiguity |
| Applications | `is.andri.komms` on desktop, Android, and iOS; `Komms` product name | Store/package migrations, signing identities, platform preferences/keychain namespaces, deep links, user-recognizable upgrade path |
| Distribution | `Komms-*.dmg/.msi/.apk`; `ghcr.io/andrigitdev/komms-kultd` | Release automation, container aliases, checksums, updater metadata, operator migration |
| Source/API | `komms` module/package namespaces and user-visible command names | Binding consumers, scripts, examples, support material |
| Protocol/storage domains | strings such as `Komms-PQXDH-v1`, `Komms-DHT-Locator-v2`, and local preference keys | A brand rename need not rewrite cryptographic domain separation, but any change would require compatibility vectors and migration rather than search-and-replace |
| Legal/governance | license notices, mission policy, security contacts, future trademark policy | Policy review, provenance continuity, contributor/operator guidance |

Migration cost is therefore **material and increasing**, but still manageable
before stable identifiers, app-store listings, signed update channels, and
large-scale adoption exist. That supports a keep-and-monitor decision today,
not indefinite deferral.

## 4. Confusion controls

While the name remains:

- use the repository owner and `komms.org` in security/release references;
- describe this project as the private resilient messenger, not merely “Komms
  Protocol” without context;
- do not imply affiliation with `komms.app`, Kaspa, Hippius, Bittensor, or the
  referenced `Komms-protocol` organization;
- route misdirected reports without collecting unnecessary information and
  record the event as a confusion signal;
- keep release signing identities, checksums, package origins, and security
  contacts prominent; and
- reserve new handles/domains only when useful, without treating registration
  as legal clearance.

## 5. Monitoring cadence

Andri owns the monitoring record until the role is delegated:

1. **Monthly during Beta and stable-v1 preparation:** exact-name web, GitHub,
   app-store, package-registry, domain, and observed-project activity check.
2. **Before every public release:** verify project/release descriptions,
   package identifiers, security contacts, redirects, and new confusion
   reports.
3. **Quarterly registry checkpoint:** record the date and search coverage for
   Iceland, EUIPO/WIPO, and jurisdictions where distribution or adoption has
   become material. The next checkpoint is 2026-10-26.
4. **Event-driven review:** run immediately on any trigger below.

Each review is appended through a dated change to this file or a linked public
record. Silence is recorded as “no new observation,” not “cleared.”

## 6. Triggers for qualified trademark advice

Qualified advice becomes proportionate before the project:

- files or opposes a trademark application;
- freezes stable brand, package, update, or long-lived public wire identifiers;
- enters an app store, paid distribution, material fundraising/grants,
  sponsorship, operator contracts, or paid promotion;
- expands sustained targeting beyond Iceland or into a jurisdiction with a
  relevant observed right;
- grants official operator status or a trademark licence; or
- incurs a rename cost materially greater than the one recorded here.

Advice is sought immediately if:

- a user, contributor, operator, press contact, search result, or security
  reporter actually confuses the two communication projects;
- `komms.app`, another claimant, a platform, or counsel contacts the project
  about the name;
- a cease-and-desist letter, opposition, takedown, package dispute, domain
  dispute, or store rejection occurs;
- a relevant identical/similar application or registration is found; or
- the other project begins overlapping distribution, app-store, protocol,
  operator, or nonprofit messaging activity in a way that increases likely
  confusion.

These triggers require a qualified assessment; they do not predetermine keep,
coexistence, adjustment, or rename.

## 7. Rename review criteria

If a trigger fires, the founder records:

- claimant/right and verified priority;
- goods/services and jurisdictions;
- evidence of actual or likely confusion;
- user-safety and security-update consequences;
- coexistence or qualifier options;
- migration sequence for domains, signed artifacts, package identities,
  protocol compatibility, and redirects; and
- the cost of changing now versus after the next release stage.

Until that review changes this record, the decision remains: **continue using
Komms for now, monitor monthly, and do not represent the name as legally
cleared.**
