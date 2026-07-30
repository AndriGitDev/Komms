# Komms native-wake gateway operator record

## Current status

| Field | Published value |
|---|---|
| Deployment status | **Not deployed** |
| Service provider | Not applicable; no running gateway |
| Administrative domain | Not assigned |
| Hosting provider / region | No target authorized |
| Public HTTPS origin | Not assigned |
| Source revision | No deployed revision |
| OCI image digest | No deployed image |
| Configuration digest | No deployed configuration |
| Enabled native providers/topics | None |
| TLS and capability-key fingerprints | No production keys generated |
| Native-provider credential ids | No production credentials enrolled |
| State epoch / first start | Not applicable |
| Uptime history | No operational history |
| Material incidents | None operational; service has not run |
| Last updated | 2026-07-30 |

The validated artifact can enable exactly one role: fixed-shape,
capability-gated APNs/FCM wake. This page does not claim deployment,
independent operation, Private-mode non-collusion, guaranteed wake or
background execution, anonymity from the operator/host/native provider,
forensic erasure, or inability of an administrator to log, correlate,
suppress, replay, or deny service.

## Publication record required before operation

| Field | Required operator value |
|---|---|
| Legal/service provider | Name responsible for the gateway |
| Administrative domain | Entity controlling host, DNS, TLS, and service keys |
| Hosting provider and region | Provider and broad region |
| Public origin | Canonical HTTPS origin and pinned TLS leaf SHA-256 |
| Source revision | Complete 40-character Git revision |
| Image | Registry name plus immutable OCI index digest |
| Configuration | Public redacted configuration plus SHA-256 digest |
| Capability keys | Active/overlap ids and public fingerprints |
| Native provider | APNs and/or FCM, credential id, allowed official topics |
| Capability retention | Maximum lifetime and key-overlap period |
| Durable state | Revocation/replay row limits and no-stale-restore procedure |
| Connection/rate limits | Published global, source, capability, destination bounds |
| Logs and metrics | Disabled access/body logs; exact aggregate health fields |
| Direct/Private ingress | Direct, Tor, or OHTTP path and administrative domains |
| Start and uptime | Start date and append-only outage history |
| Incidents | Date, scope, affected credential, metadata risk, disposition |
| End of life | Notice date, replacement/overlap, shutdown/key-disable date |

## Data and authority boundary

The running gateway sees direct-ingress network addresses, timing, volume, and
availability. When it opens a valid capability it sees the native provider
token, application topic, static notification profile, expiry, and random
capability id. APNs or FCM sees the destination token, gateway/native
credential, timing, source service, and one static payload profile.

The implemented request contains no Komms sender or recipient identity,
conversation/group id, message id, message type, text, media, unread count,
message timestamp, message ciphertext, ratchet key, delivery receipt, contact
graph field, directory key, release key, or account/device private key.

Cryptography and typed client state prevent the gateway from decrypting
messages or advancing `queued`, `sent`, or `delivered`. They do not prevent a
host administrator, hosting provider, or native provider from observing its
own metadata, delaying or dropping work, changing software, logging future
requests, inspecting live memory, or sending/withholding generic
notifications.

The complete build, hardening, state-loss, rotation, incident, self-hosting,
replacement, and rollback procedure is in the
[native-wake runbook](37-native-wake-operations.md).
