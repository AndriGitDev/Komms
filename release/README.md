# Release control files

This directory contains source-controlled policy and empty qualification
contracts. It contains no signing private key, token, password, provisioning
profile, store credential, or production signature.

- `policy-v1.json` defines release channels, separately scoped signing roles,
  retention, artifact classes, update paths, and the records required before a
  stable claim.
- `qualification-matrix-v1.json` defines the install, upgrade, rollback,
  compatibility, update, and compromise-response cases that must be run on
  named supported environments.
- `residual-risks-v1.json` keeps the current stable decision visibly blocked
  until credential, independent, and physical evidence is supplied.
- `stable-beta-plan-v1.json` fixes the consent boundary, aggregate pilot
  metrics, final-candidate reruns, P0 closure evidence, support window,
  rollback triggers, and candidate-only founder decision.
- `stable-beta-release-notes-template.md` is deliberately unfilled product
  copy for a future evidence-bound candidate; it is not a release note or
  stability claim.
- `android-license-policy-v1.json` maps the exact locked Android graph to
  upstream declared expressions without treating the inventory as legal
  review. Optional verified POMs are a cross-check, not a host-cache dependency.
- `toolchain-v1.json` pins release compilers, SDK/NDK packages, packaging
  generators, bootstrap checksums, validation tools, the Dockerfile frontend,
  and container bases.
- `keys/` accepts public verification material only. No release-manifest key is
  currently enrolled.

The operational procedure and credential boundaries are in
[Release security and recovery](../docs/39-release-security-and-recovery.md).
The evidence format and local commands are in
[Release evidence bundles](../docs/40-release-evidence-bundles.md).
The pilot, gate-audit, support, rollback, and go/no-go procedure is in
[Stable-beta pilot and release decision](../docs/51-stable-beta-pilot-and-release-decision.md).
