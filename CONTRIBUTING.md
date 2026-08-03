# Contributing to Komms

Komms 0.3 Alpha is a packaged public prerelease. Its core, transports, local
RPC/CLI and UniFFI surfaces, and desktop/Android/iOS shells are implemented,
with automated evidence in many areas. Clean-install internet use, abuse
admission, mailbox durability, hardware/device qualification,
production-signed distribution, independent review, and other P0 gates remain.
Testers can start with the [Alpha testing guide](docs/27-alpha-testing.md);
current priorities and evidence language are in the
[stabilization program](docs/29-stabilization-program.md).

Komms is currently founder-directed. Contributions provide ideas,
implementation, testing, and evidence; product and release authority remains
with the founder unless explicitly delegated.

## Where contributions help

Open an issue for anything in `docs/` that is wrong, unclear, or missing:

- **Highest value**: holes in the [threat model](docs/02-threat-model.md), flaws in the
  [crypto spec](docs/04-cryptography.md), unrealistic assumptions in the
  [transport design](docs/05-transports.md) (LoRa airtime math especially; field
  experience with Meshtastic very welcome).
- Disagreement with a recorded decision? Respond to the specific
  [ADR](docs/adr/README.md) and address the alternatives it already weighed.
- Implementation work should start from the current gaps in the
  [stabilization program](docs/29-stabilization-program.md). The
  [roadmap](docs/08-roadmap.md) and
  [feature delivery plan](docs/12-feature-delivery-plan.md) are implementation
  inventories, not permission to expand scope ahead of P0 work.

Small documentation, test, accessibility, localization, and reproducibility
improvements are welcome without first running the full release matrix. An
issue is useful for design or ambiguous scope, but a focused, noncontroversial
fix does not require advance permission.

The [bounded contributor path](docs/44-contributor-path.md) provides named
profiles for protocol, storage/node, desktop, Android core, iOS core, and
documentation work. A newcomer can inspect and run one profile without release
credentials:

```sh
python3 scripts/contributor-check.py --list
python3 scripts/contributor-check.py PROFILE
```

## Implementation changes

- Install Rust 1.88 or newer; CI compiles the workspace at exactly 1.88 to keep
  the declared MSRV honest. The full fuzz gate also needs nightly Rust,
  `cargo-fuzz`, and `cargo-deny`. Platform-specific prerequisites are listed in
  each app README.
- Read [09: Implementation Guide](docs/09-implementation-guide.md) first; it defines
  crate boundaries, crypto coding standards, and review gates. Checked-in APIs
  are authoritative. PRs that change design without an ADR will be redirected
  to the ADR process, kindly.
- For an ordinary PR, run formatting plus the narrowest affected unit,
  integration, clippy, and shell checks, and list exactly what ran. Reviewers
  may request a broader check when a shared contract changes. The complete
  [local release gate](docs/24-local-release-gate.md)—all targets, generated
  bindings, fuzz smoke, dependency policy, and platform evidence—is required
  for a publication candidate, not every contributor edit.
- Start with one checked-in contributor profile when it fits. These profiles
  build or validate one bounded target, strip signing/provider credentials from
  child processes, and contain no push, tag, signing, upload, merge, or release
  action.
- Update the README/status table, affected design or feature contract, platform
  guide, and ADR index whenever behavior, requirements, compatibility, or a
  release gate changes. Documentation claims must distinguish automated build
  evidence from hands-on device or hardware qualification.
- Keep PRs scoped to one concern; cite the spec section your change implements.
- The human submitter must understand and take responsibility for the diff,
  verify that they have the right to submit it, check license and provenance
  concerns, run the applicable tests, and be able to explain and revise the
  result.

## Process

- **Issues** for design discussion; **PRs** for concrete text/code changes.
- Issues labelled `good first change` name exact scope, exclusions, acceptance
  criteria, the recommended contributor profile, and sensitive review routing.
  The repository issue form and label definitions preserve that contract.
- ADRs follow [docs/adr/template.md](docs/adr/template.md) and appear in the
  [ADR index](docs/adr/README.md). New ADRs are numbered sequentially.
  Normative decisions in an accepted ADR change through a superseding ADR;
  factual corrections, security-boundary clarifications, and cross-reference
  repairs may be made in place when they do not silently reverse the recorded
  decision.
- Be direct about problems and generous with people. Security arguments win on merit,
  not volume.
- Participation follows the [Code of Conduct](CODE_OF_CONDUCT.md). Roles,
  decisions, review requirements, and current ownership are documented in
  [GOVERNANCE.md](GOVERNANCE.md) and [MAINTAINERS.md](MAINTAINERS.md).

## Licensing of contributions

By submitting a contribution, you represent that you have the right to submit it
and agree that it may be distributed under [AGPL-3.0-only](LICENSE), the
applicable repository license. No contributor license agreement is currently
required. Identify copied, generated, employer-owned, or third-party material
and preserve its notices; the complete scope and asset rules are in
[License, Trademark, and Asset Policy](docs/47-license-trademark-assets.md).
