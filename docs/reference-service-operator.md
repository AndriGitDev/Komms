# Komms reference-service operator record

## Current status

| Field | Published value |
|---|---|
| Deployment status | **Not deployed** |
| Service provider | Not applicable; no running reference service |
| Administrative domain | Not assigned |
| Hosting provider / region | No target authorized |
| Public service domain | Not assigned |
| Source revision | No deployed revision |
| OCI image digest | No deployed image |
| Configuration digest | No deployed configuration |
| Enabled roles | No roles currently operated |
| Runtime key fingerprints | No production keys generated |
| First production start | Not applicable |
| Uptime history | No operational history |
| Material incidents | None operational; service has not run |
| Last updated | 2026-07-30 |

The validated artifact can enable exactly two roles: libp2p
bootstrap/Kademlia cache and short-lived pairwise rendezvous. Deployment
requires a separate explicit authorization and a completed revision- and
digest-bound table below. This page does not claim an independent operator,
Private-mode non-collusion, anonymity from an operator or host, durable mailbox
delivery, forensic erasure, or inability of an administrator to log,
correlate, suppress, replay, or deny service.

## Publication record required before operation

| Field | Required operator value |
|---|---|
| Legal/service provider | Name responsible for the deployment |
| Administrative domain | Entity controlling host, DNS, and service keys |
| Hosting provider and region | Provider and broad region |
| Public domain/origin | HTTPS origin and libp2p multiaddresses |
| Enabled roles | `bootstrap-kad-cache`, `pairwise-rendezvous` only |
| Source revision | Complete 40-character Git revision |
| Image | Registry name plus immutable OCI index digest |
| Configuration | Public redacted config plus SHA-256 digest |
| libp2p service key | PeerId and SHA-256 public-key fingerprint |
| TLS/provider service key | Leaf certificate SHA-256 / provider static key |
| DHT retention | Local TTL, row count, combined value bytes |
| Rendezvous retention | Maximum TTL, rows, accounted mutable bytes |
| Connection/rate limits | Published global and per-ingress bounds |
| Mutable storage | tmpfs/process RAM only; no persistent volume |
| Logs and metrics | Disabled request/access/body logs; named aggregates only |
| Start and uptime | Start date and an append-only outage history |
| Incidents | Date, scope, affected service key, metadata risk, disposition |
| End-of-life | Notice date, replacement/overlap, shutdown date |

## Data and authority boundary

The service receives opaque discovery locators/records and opaque pairwise
rendezvous slots/records. It also sees network addresses, timing, volume and
availability at direct ingress. It receives no Komms user identity private key,
message/media plaintext, contact graph field, mailbox deposit, wake token,
delivery authority, directory-signing key, or release-signing key through its
implemented APIs.

Client signatures and authenticated encryption prevent the deployed service
from creating an accepted account/device authority record or decrypting
message content. They do not prevent a host administrator or provider from
observing live metadata, changing the software, logging future requests,
inspecting memory, replaying still-valid ciphertext, returning garbage,
selectively suppressing records, or taking the service offline.

The complete build, host, rotation, incident, self-hosting, replacement, and
rollback procedure is in the
[reference-service runbook](35-reference-service-operations.md).
