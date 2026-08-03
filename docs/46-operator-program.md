# 46: Operator Program and Sustainable Capacity

This program turns each Komms network role into an explicit operational
boundary with a named artifact, resource model, support lifecycle, abuse
response, and public evidence record. It does not claim that a service is
deployed, independently operated, sustainable, or qualified merely because a
container, runbook, or local test exists.

The machine-readable source of truth is
[`operations/v1/roles.json`](../operations/v1/roles.json). As of 2026-07-31,
no project reference service, native-wake gateway, qualified mailbox, OHTTP
relay, OHTTP gateway, or external default operator is deployed.

## 1. Role boundary and current status

| Role | Current artifact | Mutable state | Current status |
|---|---|---|---|
| Bootstrap/Kademlia cache | `kult-reference-service --roles bootstrap-kad-cache` | bounded process memory/tmpfs | Independently selectable process/image profile implemented locally; not deployed |
| Pairwise rendezvous | `kult-reference-service --roles pairwise-rendezvous` | bounded process memory/tmpfs, at most two hours | Independently selectable process/image profile implemented locally; not deployed |
| Durable mailbox v2 | `kult-mailbox` | separately keyed encrypted SQLite custody | Dedicated least-authority artifact implemented locally; not deployed or operator-qualified |
| OHTTP relay ingress | `kult-ohttp-relay` | bounded live exchange and volatile one-minute source buckets | Dedicated fixed-mapping relay artifact implemented locally; no gateway/client path, deployment, or non-collusion qualification |
| Native wake | `kult-wake` | bounded durable replay/revocation rows | Dedicated artifact implemented locally; not deployed |

This table is intentionally stricter than a feature checklist. The reference
service keeps user identity and message authority out of its process. Its
split profile now gives each of the two roles a separate process and exclusive
credential mount, while retaining the combined ADR-0034 profile. Mailbox v2
has a dedicated single-protocol artifact and hardened image; the older `kultd
--serve-mailbox` volunteer path remains supported but is not the operator
profile. The OHTTP relay is a separate fixed-mapping process with no gateway
HPKE key; it does not make OHTTP selectable in clients and does not provide a
gateway or non-collusion evidence. The remaining end-to-end and external gaps
are implementation and qualification gaps, not documentation details, and the
validator requires them to remain visible.

No role may hold a user account or recovery private key, message plaintext,
message key, provider-directory signing key, or release-signing key. Runtime
service identities, TLS keys, mailbox row keys, wake capability keys, and
native-provider credentials stay separate from one another. A service operator
or host administrator can still observe live metadata, alter software, inspect
memory, log future requests, suppress work, or deny service.

## 2. Version and support policy

Every operator record identifies:

- the exact 40-character source revision and immutable image digest;
- the configuration digest and enabled role set;
- service-key fingerprints and their rotation epoch;
- declared capacity, retention, region, provider, and administrative domain;
- the source-offer location for the deployed covered version;
- start, outage, upgrade, incident, and end-of-life dates; and
- the exact evidence commands and retained results.

Beta operation is best effort, has no stable compatibility window, and targets
14 days' notice for a planned incompatible operator change where risk permits.
A future stable-candidate operator profile activates only through the founder's
release decision, requires a tested replacement overlap, targets at least 90
days of security support for its declared line, and gives at least 180 days'
planned end-of-life notice. Emergency containment can be immediate; the
operator then publishes why normal notice was unsafe.

An operator supports only the revision and roles named in its record. A
provider-directory entry is discovery configuration, not a warranty, identity
authority, or permanent appointment.

## 3. Capacity and cost records

The committed reference profile reserves 512 MiB RAM and two CPU cores with no
persistent mutable storage. The OHTTP relay reserves 256 MiB and one CPU with
no persistent mutable storage. The wake and dedicated mailbox profiles each
reserve 384 MiB RAM and two cores plus their distinct durable volumes. Mailbox
v2's default 64 MiB ciphertext limit requires at least 256 MiB of writable space
for indexes, seals, WAL, metadata, and reserve; an operator should provision at
least 1 GiB until an observed workload justifies another bound.

For each role and month, record:

| Input | Required observation |
|---|---|
| Compute | instance price, CPU/RAM reservation, peak and p95 use |
| Persistent storage | allocated and used GiB, IOPS, reserve, backup cost where allowed |
| Network | included and metered ingress/egress, peak rate, overage |
| Requests | accepted, refused, malformed, rate-limited, expired, and overload aggregates |
| Human operations | upgrades, abuse handling, incidents, on-call time, and accessibility/support work |
| Funding | project subsidy, donation/grant allocation, operator fee, or unreimbursed amount |

Do not publish a universal “cost per user.” The services deliberately do not
hold a stable user identity, and a transport peer can rotate. Capacity planning
uses aggregate items, bytes, operations, connections, expiry work, and observed
resource use.

Before accepting new custody or work, every service checks its item, byte,
connection, concurrency, rate, memory, and disk bounds. Overload refuses or
defers work without converting it into `sent` or `delivered`. A capacity
increase requires the same privacy and crash review as the original bound; it
is not an unreviewed configuration tweak.

## 4. Abuse and incident response

An operator may enforce content-blind connection, request, item, byte,
retention, and resource limits. It may block abusive network sources or
service capabilities where law and safety permit, but must not add message
content, account identity, contact labels, or social-graph fields to do so.
“Per client” controls are containment, not a Sybil-resistant identity claim.

The response sequence is:

1. preserve bounded aggregate evidence and the exact deployed revision/config;
2. refuse new work before overcommit and preserve unrelated custody;
3. identify the affected role, credential domain, time window, and metadata;
4. isolate or remove only the affected provider default;
5. rotate the affected runtime credential without reusing directory or release
   keys;
6. keep direct, DHT, mailbox, LAN, mesh, and sneakernet fallback available
   where the affected role permits; and
7. publish outage, custody-loss, metadata-risk, user-action, and residual-risk
   statements through the operator record and authenticated project channels.

The full cross-role process is in
[Privacy, Legal, and Incident Readiness](49-privacy-legal-incident-readiness.md).

## 5. Upgrade, rollback, and end of life

An upgrade pins old and new revisions, images, configurations, and service-key
sets. Run the role's smoke and conformance checks before opening traffic.
Mailbox upgrades stop custody, take one complete encrypted database/key
snapshot, verify schema and lease/ack behavior, and roll back only with the
matching snapshot. Reference-service restart intentionally loses RAM state.
Wake state must never be rolled back independently of its active capability
keys; uncertain state disables every affected key version.

End of life follows the longest relevant advertised TTL or capability
lifetime:

- stop accepting new defaults or registrations;
- publish the end date and optional replacement without making it mandatory;
- overlap only for the documented safe window;
- preserve sender custody and client fallback;
- disclose any mailbox rows that may outlive the operator; and
- disable and destroy retired service credentials after the overlap.

## 6. Two-operator onboarding and conformance

[`operator-records.json`](../operations/v1/operator-records.json) reserves two
external slots without inventing names, organizations, or independence. A real
operator qualifies a slot only after supplying:

1. a distinct responsible operator and administrative domain;
2. a clean build or verified immutable image tied to the same source revision;
3. redacted configuration, public key fingerprints, source offer, retention,
   resource, cost, and data-flow disclosures;
4. role-specific smoke, overload, restart, upgrade, rollback, blackhole, and
   incident results;
5. the stand-alone conformance runner result where the role has a protocol
   adapter;
6. observed capacity and expense for the declared evaluation interval; and
7. a signed or otherwise attributable independence/conflict statement.

The two records must name distinct operator names and administrative domains.
Two containers, accounts, or hosts controlled by the same person do not prove
plural operation or Private-mode non-collusion. No current record qualifies.

## 7. Validation and open evidence

Run:

```sh
python3 scripts/check-stewardship.py
python3 scripts/test-stewardship.py
```

The checks verify the complete role inventory, truthful deployment statuses,
two empty external slots, provider data-flow coverage, funding-report shape,
asset notices, and incident dry-run decisions. They are local policy evidence,
not an operator deployment or an independent exercise.

P1-04 remains open until two real external operators complete the record.
Separated OHTTP client/gateway operation and non-collusion, production
capacity/cost history, and independently observed upgrade and incident runs
also remain open. The split reference profile, dedicated mailbox
[runbook](50-mailbox-service-operations.md), and dedicated OHTTP
[runbook](52-ohttp-relay-operations.md) close local process-isolation gaps
only.
