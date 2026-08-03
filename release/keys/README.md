# Release public keys

No production release key is enrolled.

This directory may contain public verification material only. The first
release-manifest identity is enrolled by a maintainer after an offline,
hardware-backed key is generated, its recovery copies are tested, and its
fingerprint is reviewed through the `release-signing-enrollment` environment.
The resulting `allowed_signers` file uses the OpenSSH allowed-signers format
with principal `komms-release-v1`.

Private keys, recovery seeds, PINs, passwords, provisioning profiles, API
keys, keystores, certificates containing private material, and store
credentials must never enter this directory, any repository file, a workflow
log, an issue, or a release attachment.

Until `allowed_signers` exists and the other platform roles in
[`policy-v1.json`](../policy-v1.json) are enrolled and exercised, the release
workflow cannot publish an Alpha, Beta, or stable candidate.
