# 49: Privacy, Legal, and Incident Readiness

This runbook joins the threat model, provider data flows, lawful-request
handling, service-key incidents, advisories, and user notification into one
bounded process. It does not promise that operators cannot observe metadata,
that a request can always be disclosed, or that a single-maintainer project
has 24/7 coverage.

The exact current data inventory is
[`operations/v1/data-flows.json`](../operations/v1/data-flows.json). No
production project service is deployed, and qualified legal counsel and a
backup security steward are **Unassigned**.

## 1. Provider visibility and retention

| Flow | What the operator/provider can observe | Project-service retention |
|---|---|---|
| Direct libp2p | network addresses, timing, volume, padded ciphertext | none at a project service |
| Bootstrap/DHT cache | source address, timing, volume, opaque locator and fixed encrypted record | process memory, at most configured 48-hour TTL |
| Pairwise rendezvous | source address, timing, volume, opaque slot and fixed ciphertext | process memory, at most two hours |
| Mailbox v2 | source/pseudonymous client, opaque token index, timing, padded size, expiry, lease/quota outcome | durable ciphertext up to 30 days, registration up to 60 days, lease 120 seconds in the committed profile |
| Direct native wake | source address plus capability-opened native token, topic, static profile, expiry, timing | bounded replay/revocation rows no longer than capability expiry |
| APNs/FCM | destination token, gateway credential, app topic/profile, timing and provider account | governed by the native provider, not erased by Komms policy |
| Tor Private ingress | gateway sees Tor exit rather than client source; other timing/target-side fields remain | same target-service retention |
| OHTTP relay ingress | relay sees client address, fixed gateway, timing, volume, fixed outer size and availability; gateway sees relay address plus the decapsulated target method, URI, headers, and body | live bounded exchange only; no project deployment or qualified end-to-end path |
| Releases/stores | download address, timing, artifact/store choice and ordinary account metadata | governed by the named host/store; Komms implements no product analytics |

Row encryption and fixed shapes reduce exposure; they do not remove live
operator access. A common host, DNS account, network, credential custodian, or
administrator can correlate roles. Process isolation or different containers
under common control is not non-collusion.

## 2. Data minimization and telemetry

Official services use only role-specific aggregate health: item/byte totals,
capacity, expiry, overload, malformed/refused operations, uptime, and reduced
provider outcomes. They do not retain request/body/access logs, per-user
traces, stable account identifiers, contact labels, tokens, locators,
ciphertext, row ids, capabilities, message ids, or social graphs in metrics or
ordinary logs.

Incident diagnostics do not silently expand that boundary. Packet captures,
memory dumps, access logging, or distributed tracing require an explicit
incident decision, minimization plan, access list, retention deadline, and
public disposition where disclosure is safe. The RAM-only reference profile
forbids those captures as routine evidence.

## 3. Lawful or compulsory requests

On receiving a request:

1. preserve the exact request, receipt time, deadline, delivery method, and
   access list in a private incident record;
2. verify the sender, authority, jurisdiction, scope, and any secrecy term;
3. seek qualified counsel where proportionate; counsel is currently
   unassigned;
4. inventory only information actually controlled by the named project or
   operator role;
5. challenge, narrow, or appeal requests that are defective, overbroad, or
   inconsistent with applicable rights where lawful and proportionate;
6. do not create new logging, decrypt content the service cannot ordinarily
   open, or collect data merely to make it available;
7. disclose only the authorized minimum through a controlled channel;
8. notify affected users before disclosure when legally permitted and safe, or
   afterward when a restriction expires; and
9. publish a bounded aggregate transparency entry that does not identify a
   person or defeat a lawful protection.

Komms does not claim that every request can be resisted, that an operator holds
no useful metadata, or that a host cannot be compelled to change future
behavior. A request affecting service availability, keys, or software becomes
a security incident even when legally valid.

## 4. Incident classes and containment

| Class | Immediate containment |
|---|---|
| Account/device protocol defect | preserve report, identify affected revision/state, disable unsafe feature or release, prepare atomic fix and migration |
| Release or update key | freeze publication, remove affected artifact, revoke/rotate role key, rebuild from reviewed source, publish exact digests |
| Provider-directory key | reject new generations, retain last-valid/manual paths, rotate offline root through the authenticated procedure |
| Reference libp2p key | remove old bootstrap address, overlap a new service-only PeerId, update signed configuration |
| Rendezvous TLS/provider key | move to authenticated parallel origin/key, update paired controls/directory, remove old origin after overlap |
| Mailbox transport key | withdraw old address, publish replacement, preserve/disclose custody window |
| Mailbox row key/database | isolate, restore only a complete matching snapshot, disclose token/timing/ciphertext metadata and possible row loss |
| Wake capability key | disable affected key immediately, register fresh capabilities, preserve ordinary delivery fallback |
| Wake state rollback/loss | disable every key active in the uncertain interval; never restore stale revocation state |
| APNs/FCM credential | revoke at provider, enroll a distinct replacement for exact topics, disclose notification/token risk |
| OHTTP relay TLS key/host | withdraw relay mapping, rotate only relay TLS identity, rebuild separately, disclose ingress metadata window |
| OHTTP gateway/CA | stop forwarding, withdraw mapping, authenticate a new gateway/CA; never import the gateway HPKE key into the relay |
| Host/common administrator | remove all affected roles/defaults, revoke each credential domain separately, rebuild on reviewed infrastructure |

Containment never reuses account, recovery, directory, release, mailbox,
rendezvous, wake, or native-provider keys across roles.

## 5. Severity, advisory, and user notification

The private incident record names discovery time, affected revisions/services,
known and possible impact, evidence custody, severity, containment, owner,
notification decision, fix/retest, and residual risk. Use the response targets
in [`SECURITY.md`](../SECURITY.md); they are goals, not round-the-clock
coverage.

A public advisory states:

- affected and unaffected versions, roles, platforms, and dates;
- confidentiality, integrity, metadata, availability, and custody impact;
- exploit prerequisites and safe reproduction detail;
- fixed revision/artifact digest and verification steps;
- workaround, key rotation, user action, and operator action;
- external report credit or anonymity preference;
- tests/retest and every open external gate; and
- residual risk and the next update date.

Use authenticated release, advisory, provider-directory, and in-product
channels that remain trustworthy. A compromised channel is not used to
authenticate its own replacement. Notifications minimize stable identifiers
and do not expose contact relationships or individual request timelines.

## 6. Internal policy dry-runs

The scenarios in
[`operations/v1/tabletops.json`](../operations/v1/tabletops.json) exercise:

1. runtime service-key or host compromise;
2. a lawful/compulsory information request;
3. cross-role administrative correlation; and
4. overload and operator end of life.

The repository validator confirms that each dry-run contains required
containment and rejects unsafe shortcuts such as key reuse, stale wake-state
restore, false `sent` claims, hidden mailbox deletion, or a Private
non-collusion claim under common control.

These are deterministic policy dry-runs, not a live incident, external legal
review, independent tabletop, operator exercise, or evidence that a person
received a notification. A real rehearsal must name participants, deployed
revision, time, communications, decisions, failures, and retest disposition.

## 7. Continuity and open gates

The founder is the current coordinator. No backup security steward, legal
counsel, 24/7 operator, external incident evaluator, or independently
administered service exists. If the founder is unavailable, repository and
provider access alone does not grant project authority; the continuity gate in
governance remains open.

Run:

```sh
python3 scripts/check-stewardship.py
python3 scripts/test-stewardship.py
```

P1-07 remains open until a named human exercise, qualified legal disposition
where proportionate, real operator incident/notification drill, and backup
stewardship are retained. The local dry-runs prove only that the source
policies agree and fail closed on the tested unsafe decisions.
