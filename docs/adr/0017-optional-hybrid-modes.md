# ADR-0017: Optional hybrid modes preserve a server-independent core

- **Status**: Proposed
- **Date**: 2026-07-15

## Context

Komms is useful only if ordinary people receive messages reliably on mobile
platforms, behind NAT, and after long periods in the background. The existing
decentralized design already provides direct libp2p delivery, signed DHT
discovery, recipient-selected volunteer mailboxes, LAN, mesh, and sneakernet.
Those paths remain sufficient for communication, but mobile operating systems
can suspend an application before it can refresh routes or collect queued mail.
Native APNs and FCM wake-up can improve that experience, and a short-lived
post-pairing rendezvous record can avoid publishing a contact's current route
under their public identity.

Introducing those services changes the old absolute statement that there is no
service provider. Even when a service receives no message plaintext or public
Komms identity, its network position may expose source addresses, request time,
target capabilities, provider tokens, and traffic volume. A compelled or
compromised operator may log, suppress, replay, throttle, or selectively deny
requests. Apple and Google necessarily observe native push delivery to an app
instance. None of those facts is compatible with claiming that optional
infrastructure has "zero" metadata visibility.

The product therefore needs explicit modes and one invariant stronger than a
marketing label: disabling or losing every optional service must leave the
existing protocol and all local keys, history, queues, discovery paths, and
off-grid transports functional.

## Decision

### 1. Komms has one core and three explicit operating modes

The wire protocol, identity, ratchets, sender-key groups, envelopes, mailbox
delivery, and local store are identical in every mode. Modes select only
optional discovery privacy and wake-up behavior:

| Mode | Pairwise rendezvous | Native wake | Intended disclosure |
|---|---|---|---|
| **Sovereign** | Disabled; existing DHT, out-of-band, LAN, mailbox, mesh, and sneakernet paths only | Disabled | No optional Komms-operated service |
| **Private** | Recipient-selected rendezvous through Tor or a non-colluding [Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html) relay | Optional native wake through anonymized ingress | Wake gateway and APNs/FCM still learn the destination and delivery time |
| **Standard** | Direct HTTPS to recipient-selected rendezvous providers | APNs on Apple platforms; FCM in the Google Play Android flavor | Provider sees the connecting address, opaque target, timing, and volume |

Enabling Private or Standard mode requires an explicit, reversible choice with
a concise disclosure. A build may recommend a mode during onboarding, but it
must not silently enable a convenience service, and the applications must show
which mode is active. Changing mode never rotates or replaces the user's Komms
identity.

### 2. Optional services are accelerators, never authorities

No optional service may:

- receive message plaintext, attachment keys, ratchet state, sender-key state,
  identity private keys, contact petnames, group membership, or local metadata;
- authenticate a peer, establish trust, mint a Komms identity, decide message
  ordering, or advance a delivery state;
- make a message depend on service availability after it has entered the
  ordinary durable Komms queue; or
- introduce an unencrypted or server-decryptable messaging fallback.

Rendezvous returns only end-to-end authenticated encrypted delivery hints.
Native push carries a static content-free or generic wake indication. A sender
emits a wake request only after a direct peer or mailbox relay has accepted the
sealed envelope. The encrypted delivery receipt remains the only transition to
`delivered`; a push-provider acknowledgement is never a message receipt.

### 3. The threat model distinguishes content safety from metadata exposure

The following is the maximum honest claim for the optional layer:

> Compromise or seizure of an optional service does not reveal Komms identity
> private keys or message/media plaintext and does not let the service forge an
> accepted message. It may reveal service-use metadata and may delay, suppress,
> replay, or selectively deny convenience operations.

Per service, the normal observable surface is:

| Observer | May observe |
|---|---|
| Rendezvous gateway | Connecting address unless hidden, opaque slot, operation, timing, fixed request/response size, expiry |
| OHTTP/Tor ingress | Client network address and gateway destination, but not the protected target request |
| Native wake gateway | Opaque capability, native provider token after capability opening, app topic/environment, timing and provider result |
| APNs/FCM | App/provider token, delivery time, priority, static notification shape, platform/device telemetry under provider policy |
| Passive global observer | Potential correlation across client, relay, gateway, and provider traffic; not a Komms security guarantee |

Pairwise capabilities prevent public-key scraping from directly producing a
route or wake target. They do not make a peer, a service operator, or a global
observer incapable of traffic analysis. Registrations made together may also
be correlated operationally unless the client separates and anonymizes them.

### 4. Rendezvous is federated; native push egress has platform limits

Recipients choose zero or more rendezvous providers and convey provider
descriptors inside the existing authenticated pairwise channel. Providers are
self-hostable, use provider-specific capabilities, and are never placed in a
mandatory global list. Clients retain static/out-of-band and signed DHT hints
alongside expiring rendezvous hints and may query redundant providers.

Native push is different. APNs and FCM credentials are bound to the distributed
application identity and cannot safely be handed to arbitrary community
operators. The official application may therefore use one or more controlled
egress gateways while accepting independently operated, non-colluding OHTTP
relays. A separately built application can use its own provider credentials.
The Google-free Android artifact remains available and contains no FCM SDK;
adding UnifiedPush or another distributor is a separate compatibility decision.

### 5. Optional-service data is minimized operationally

Services use fixed-size protocol bodies, no query-string capabilities, no
application analytics, no per-request access logs, and no plaintext request
bodies in reverse-proxy, CDN, WAF, tracing, crash, or error systems. Aggregate
capacity and health metrics may not contain slot values, wake capabilities,
native provider tokens, or full client addresses.

RAM-only rendezvous storage is a retention reduction, not a forensic-erasure
guarantee. Swap, core dumps, persistence, snapshots, and unattended diagnostic
capture are disabled; clean shutdown performs best-effort zeroization. Abrupt
termination, kernel buffers, allocator copies, and a hostile host remain outside
that guarantee. Native push state follows ADR-0019 and may use durable protected
gateway keys or encrypted token mappings where availability requires it.

### 6. Failure always collapses toward the sovereign core

Every optional client has bounded exponential backoff, jitter, a circuit
breaker, and a manual disable control. Failure does not erase static hints,
replace signed DHT data, fail a queued message, or generate mesh airtime.
Applications surface degraded convenience honestly and continue the existing
delivery ladder. A deployment in which blocking the default service prevents
communication fails this ADR.

## Alternatives considered

### Keep the absolute serverless claim and add services quietly

Rejected. The claim would become false in the modes most ordinary users run,
and it would hide exactly the metadata boundary that high-risk users need to
understand.

### Make rendezvous and push mandatory for reliable mobile messaging

Rejected. It would turn an optional convenience service into an availability
authority and contradict A4, off-grid operation, and the project's purpose.

### Send sealed messages through APNs/FCM

Rejected. Even encrypted application payloads would add a mandatory provider
message path, size/timing leakage, retention ambiguity, and pressure to treat a
provider acknowledgement as delivery. Native providers carry only a wake.

### Claim anonymity because identifiers are random

Rejected. Random capabilities prevent public enumeration but do not remove IP,
timing, registration clustering, gateway-token linkage, or provider metadata.

## Consequences

- Komms can offer normal mobile convenience without weakening the sovereign
  protocol or pretending the convenience plane is metadata-invisible.
- Product copy and the threat model become mode-specific; “server-independent
  core” replaces unconditional “no servers” language.
- The default distribution must operate optional infrastructure securely and
  publish its server code, retention behavior, and availability history.
- Private mode requires at least two non-colluding administrative domains for
  OHTTP and cannot promise protection if they collude or a global observer
  correlates traffic.
- Release acceptance must blackhole every optional service and prove existing
  direct, mailbox, LAN, mesh, and sneakernet delivery remains intact.
