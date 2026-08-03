# Komms OHTTP Relay Operator Record

**Not deployed**

No project OHTTP relay, gateway, public origin, operator, administrative
domain, image digest, service-key fingerprint, uptime record, or incident
history is assigned.

The local `kult-ohttp-relay` artifact implements only the fixed-mapping RFC
9458 relay side. It has no gateway HPKE private key. It is not an end-to-end
Private-mode path and does not demonstrate non-collusion, anonymity,
independent operation, or production capacity.

Before this record can change, retain:

- the exact source revision, immutable image digest, SBOM/provenance, and
  configuration digest;
- relay TLS certificate, gateway CA bundle, and mapping fingerprints;
- the relay operator, hosting provider, administrative domain, public origin,
  fixed gateway origin, enabled body profile, limits, and source offer;
- a distinct gateway operator and administrative domain with no shared host,
  network control, credential custodian, logging plane, or incident authority;
- real-network client→relay→gateway→target interoperability, malformed,
  overload, blackhole, rotation, replacement, and failure results; and
- observed capacity/cost, uptime, incidents, external review, and explicit
  non-collusion disposition.

Local tests and an image are not operator qualification. See
[OHTTP Relay Operations](52-ohttp-relay-operations.md).
