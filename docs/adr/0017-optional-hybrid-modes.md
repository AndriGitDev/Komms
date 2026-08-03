# ADR-0017: Optional hybrid modes preserve a server-independent core

- **Status**: Accepted; operating modes implemented for Alpha
- **Date**: 2026-07-15
- **Reference deployment**:
  [ADR-0034](0034-operator-minimized-reference-discovery.md)

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
| **Standard** | Direct HTTPS to recipient-selected rendezvous providers | APNs on Apple platforms; FCM in the Google Play Android flavor | Provider sees the connecting address, opaque target, timing, and volume |
| **Private** | Recipient-selected rendezvous through Tor or a non-colluding [Oblivious HTTP](https://www.rfc-editor.org/rfc/rfc9458.html) relay | Optional native wake through anonymized ingress | Wake gateway and APNs/FCM still learn the destination and delivery time |
| **Sovereign** | Disabled; existing DHT, out-of-band, LAN, mailbox, mesh, and sneakernet paths only | Disabled | No optional Komms-operated service |

The official consumer distribution recommends and may preselect **Standard**:
an everyday user should complete onboarding without understanding DHTs, relays,
or mobile operating-system scheduling. Before the first optional-service
registration it presents one concise, reversible disclosure: message content
and identity keys stay end-to-end protected, while convenience providers and
APNs/FCM can observe limited connection/timing metadata. One confirmation
activates the recommended setup.

Private and Sovereign are available from the same onboarding review and later
under an advanced privacy/network control. They are not framed as “expert
mode” or as more virtuous choices; each has a clear reliability/privacy
tradeoff. The conversation screen shows useful state such as **Private**,
**Connected**, **Waiting for a route**, and **Fallback ready**, not internal
service names. Changing mode never rotates or replaces the user's Komms
identity.

### 1a. Public first-contact records do not publish a direct route by default

The DHT remains the self-authenticating first-contact index. In Standard and
Private modes its signed bundle carries prekeys, capabilities, and one or more
bounded introduction paths such as recipient-selected mailbox/relay
descriptors. It does not publish a current direct IP multiaddress under the
stable public account lookup by default.

After pairing, ADR-0018 supplies rotating pairwise reachability. QR/file
invites, LAN discovery, mesh, and sneakernet may carry context-specific direct
hints because they are not a globally polled identity record. Sovereign mode
may explicitly publish a direct DHT route when the user or operator needs
internet reachability without a mailbox/relay; the UI warns that anyone holding
the public address can poll that route.

### 2. Optional services are accelerators, never authorities

No optional service may:

- receive message plaintext, attachment keys, ratchet state, sender-key state,
  user Komms identity private keys, contact petnames, group membership, or local
  metadata;
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

Service operation still requires narrowly scoped service credentials such as a
libp2p identity, TLS key, or native-provider credential. Those keys grant no
user identity or message authority, remain separate from offline directory and
release-signing keys, and require explicit rotation and compromise procedures.

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

The guarantees and controls must be labelled by their enforcement source:

| Property | Enforced by | Residual operator ability |
|---|---|---|
| No message plaintext or user identity keys | End-to-end formats and APIs that never transmit those secrets | Observe network metadata and bounded ciphertext |
| No accepted message or user-record forgery | Client-side AEAD and account/device signature verification | Suppress, replay still-valid state, return garbage, or deny service |
| Bounded content leakage | Fixed-size records and capability-derived identifiers | Observe opaque slots/locators, timing, volume, and addresses |
| Reduced retention | RAM-backed state, disabled logs, short TTLs, and aggregate metrics | Change the deployment, inspect live memory, or be compelled at the host/network layer |

Project control of client signing and updates is a separate supply-chain
boundary. A content-blind service cannot protect a user running a malicious
client build.

### 4. Rendezvous is federated; native push egress has platform limits

Recipients choose zero or more rendezvous providers and convey provider
descriptors inside the existing authenticated pairwise channel. Providers are
self-hostable, use provider-specific capabilities, and are never placed in a
mandatory global list. Clients retain static/out-of-band and signed DHT hints
alongside expiring rendezvous hints and may query redundant providers.

The official Standard profile ships a signed, versioned, user-editable
directory containing multiple bootstrap, mailbox, relay, and rendezvous
operators under different administrative domains. Directory signatures prove
configuration provenance, not trustworthiness or message authenticity. A
client retains the last valid directory, supports user-supplied providers, and
never deletes sovereign routes when a directory changes. No one listed
provider is required for identity, history, or protocol validity.

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

The initial founder-operated Hetzner pilot is limited to Standard-mode
bootstrap/DHT caching and ADR-0018 rendezvous under
[ADR-0034](0034-operator-minimized-reference-discovery.md). It is not a durable
mailbox, native-wake gateway, Private-mode non-colluding deployment, or
plural-operator proof. Its administrative domain, provider, source revision,
image digest, configuration, retention policy, and incidents are public.

### 6. Failure always collapses toward the sovereign core

Every optional client has bounded exponential backoff, jitter, a circuit
breaker, and a manual disable control. Failure does not erase static hints,
replace signed DHT data, fail a queued message, or generate mesh airtime.
Applications surface degraded convenience honestly and continue the existing
delivery ladder. A deployment in which blocking the default service prevents
communication fails this ADR.

## Implemented Alpha mode profile

One `OperatingMode` contract now drives discovery publication, provider
selection, rendezvous transport, daemon status, UniFFI, desktop, Android, and
iOS. Standard and Private Connect records never publish direct routes.
Sovereign publishes one only after the separate warning acknowledgement and
always disables optional rendezvous. Manual bootstrap, relay, mailbox, LAN,
file, mesh, and sneakernet routes remain independent of directory state.

The optional provider directory is signed, versioned, bounded, parent-bound,
and replaceable. It retains a verified last-valid chain through a bounded
outage, supports an authenticated future signing-key transition, and reports
rollback, forks, corrupt retained state, and expired conflicts without choosing
authority by ordering. Removing the directory configuration disables cached
defaults without erasing user routes. No production directory, root key,
default operator, or deployment is included.

Standard rendezvous uses exact leaf-certificate pinning over TLS 1.3 after the
metadata disclosure is confirmed. Private rendezvous requires an explicit
loopback Tor SOCKS5 endpoint with proxy-side DNS and request separation; it has
no direct fallback. This is an implemented client path, not evidence that a
particular deployment is non-colluding or anonymous.

All shells expose the same mode and directory settings plus the familiar
**Connected**, **Fallback ready**, and **Waiting for a route** states. Restart
tests preserve account identity, safety numbers, verification, history, and
pending work across mode changes. The deterministic local journey gate covers
default blackhole, alternate bootstrap, replacement, pure-core operation,
first contact, offline mailbox delivery, route repair, and recovery. The exact
contract, bounds, commands, and evidence limitations are in
[Operating modes and provider configuration](../36-operating-modes-and-provider-directory.md).

ADR-0019 native wake remains unimplemented at this point. No local host,
emulator, or Simulator result qualifies a real distinct-NAT path, external
operator, mobile background lifecycle, or physical device.

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
