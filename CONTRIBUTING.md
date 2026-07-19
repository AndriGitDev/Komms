# Contributing to Komms

Komms is an alpha built from source. Its core, transports, local RPC/CLI and
UniFFI surfaces, and desktop/Android/iOS shells are implemented, while hardware
qualification, distribution, broader hardening, and explicitly design-gated
programs remain.

## Where contributions help

Open an issue for anything in `docs/` that is wrong, unclear, or missing:

- **Highest value**: holes in the [threat model](docs/02-threat-model.md), flaws in the
  [crypto spec](docs/04-cryptography.md), unrealistic assumptions in the
  [transport design](docs/05-transports.md) (LoRa airtime math especially; field
  experience with Meshtastic very welcome).
- Disagreement with a recorded decision? Respond to the specific
  [ADR](docs/adr/README.md) and address the alternatives it already weighed.
- Implementation work should start from the current gaps in the
  [roadmap](docs/08-roadmap.md) and
  [feature delivery plan](docs/12-feature-delivery-plan.md), then preserve the
  relevant security, storage, compatibility, and carrier constraints.

## Implementation changes

- Install Rust 1.88 or newer; CI compiles the workspace at exactly 1.88 to keep
  the declared MSRV honest. The full fuzz gate also needs nightly Rust,
  `cargo-fuzz`, and `cargo-deny`. Platform-specific prerequisites are listed in
  each app README.
- Read [09: Implementation Guide](docs/09-implementation-guide.md) first; it defines
  crate boundaries, crypto coding standards, and review gates. Checked-in APIs
  are authoritative. PRs that change design without an ADR will be redirected
  to the ADR process, kindly.
- Run the complete [local release gate](docs/24-local-release-gate.md): `fmt`,
  warnings-as-errors `clippy`, all tests, `no_std`, dependency policy, generated
  bindings/shell gates, and every fuzz target. Do not use hosted CI as an
  interactive compiler; publication and any hosted repetition require explicit
  maintainer authorization.
- Update the README/status table, affected design or feature contract, platform
  guide, and ADR index whenever behavior, requirements, compatibility, or a
  release gate changes. Documentation claims must distinguish automated build
  evidence from hands-on device or hardware qualification.
- Keep PRs scoped to one concern; cite the spec section your change implements.

## Process

- **Issues** for design discussion; **PRs** for concrete text/code changes.
- ADRs follow [docs/adr/template.md](docs/adr/template.md) and appear in the
  [ADR index](docs/adr/README.md); new ADRs are numbered sequentially and never
  edited after acceptance (write a superseding one).
- Be direct about problems and generous with people. Security arguments win on merit,
  not volume.

## Licensing of contributions

By contributing you agree your contribution is licensed under [AGPLv3](LICENSE), the
project license. No CLA: the license is the agreement, symmetrically, for everyone.
