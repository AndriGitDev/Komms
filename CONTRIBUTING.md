# Contributing to KommsKult

The project is in **M0 (design phase)** — the most valuable contributions are adversarial
reads of the design documents, not code (yet).

## Right now: design review

Open an issue for anything in `docs/` that is wrong, unclear, or missing:

- **Highest value**: holes in the [threat model](docs/02-threat-model.md), flaws in the
  [crypto spec](docs/04-cryptography.md), unrealistic assumptions in the
  [transport design](docs/05-transports.md) (LoRa airtime math especially — field
  experience with Meshtastic very welcome).
- Disagreement with a recorded decision? Respond to the specific
  [ADR](docs/adr/) and address the alternatives it already weighed.

## When code lands (M1+)

- Read [09 — Implementation Guide](docs/09-implementation-guide.md) first — it defines
  build order, crate boundaries, crypto coding standards, and review gates. PRs that
  change *design* without an ADR will be redirected to the ADR process, kindly.
- CI must be green: `fmt`, `clippy` (deny warnings), tests, fuzz smoke, `cargo-deny`.
- Keep PRs scoped to one concern; cite the spec section your change implements.

## Process

- **Issues** for design discussion; **PRs** for concrete text/code changes.
- ADRs follow [docs/adr/template.md](docs/adr/template.md) — new ADRs are numbered
  sequentially and never edited after acceptance (write a superseding one).
- Be direct about problems and generous with people. Security arguments win on merit,
  not volume.

## Licensing of contributions

By contributing you agree your contribution is licensed under [AGPLv3](LICENSE), the
project license. No CLA — the license is the agreement, symmetrically, for everyone.
