# Komms maintainers

Komms currently has one human maintainer. This is an intentional
founder-directed model during product construction and stabilization. It also
creates continuity and independent-assurance gaps that the project reports
honestly.

## Current maintainers

| Person | Role | Areas | Contact |
|---|---|---|---|
| Andri (`@AndriGitDev`) | Founder and lead maintainer | Product direction, merge, release, security coordination, and all unassigned areas | `andri@andri.is` |

The lead maintainer is accountable for final decisions under
[GOVERNANCE.md](GOVERNANCE.md). Being listed as code owner or maintainer does
not make self-review independent.

## Contribution and review needs

The project welcomes implementation help and qualified evidence in these areas.
These are contribution and assurance needs, not vacant shares of product
authority. Maintainer authority is delegated explicitly by the founder after
sustained, dependable participation:

- cryptography and protocol security;
- discovery, NAT traversal, mailboxes, and radio transports;
- Android and mobile lifecycle;
- iOS and mobile lifecycle;
- desktop, product accessibility, and localization;
- release signing, reproducibility, updates, and incident response;
- community stewardship, documentation, and contributor experience;
- independent security review and interoperability testing.

An interested contributor should open a public issue describing the area,
relevant experience, and work they would like to contribute. Security-sensitive
background details may be sent privately using [SECURITY.md](SECURITY.md).

## Implementation assistance

The founder intentionally uses automated analysis and implementation tools.
Those tools are not maintainers, reviewers, or independent evidence providers.
Every accepted change remains attributable to and the responsibility of the
human maintainer who approves it.

## Appointment and expectations

Maintainers are appointed by the lead maintainer after a record of constructive
contributions and dependable review in the relevant area. Maintainers are
expected to:

- follow the Code of Conduct and disclose relevant conflicts;
- review within their demonstrated expertise and say when external review is
  needed;
- keep status and evidence claims accurate;
- document material decisions and compatibility consequences;
- protect embargoed reports, release credentials, and contributor privacy;
- arrange a handoff or step down when they can no longer provide sustained
  coverage.

Appointments, responsibility changes, leaves, and removals are made by pull
request to this file. The reason for an involuntary removal is recorded unless
privacy or safety requires a narrower disclosure.

## Review coverage

[`.github/CODEOWNERS`](.github/CODEOWNERS) records current review routing.
Areas with only the founder listed still have a bus-factor and independent
assurance gap; they do not imply unassigned product authority. The release
evidence must name the actual author and reviewers; a platform approval or
CODEOWNERS match alone is not review evidence.
