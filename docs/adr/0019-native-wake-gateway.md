# ADR-0019: Native push is a capability-gated best-effort wake

- **Status**: Proposed
- **Date**: 2026-07-15

## Context

Android and iOS suspend ordinary background networking. A sealed envelope may
already be waiting at a recipient-selected mailbox while the recipient cannot
check in until the application next receives execution time. APNs and FCM can
provide a wake hint, but neither is a reliable transport and neither is
metadata-blind. The provider and gateway necessarily handle an app-instance
token and delivery time. Apple documents background notifications as
[low-priority and not guaranteed](https://developer.apple.com/documentation/usernotifications/pushing-background-updates-to-your-app),
and FCM reserves Android high priority for time-sensitive, user-visible work
and may [deprioritize invisible use](https://firebase.google.com/docs/cloud-messaging/android-message-priority).

The proposed wake must not carry message data, identify the sender, become a
receipt, or create a server mailbox. It must tolerate throttling, disabled
notifications, token rotation, application force-quit, provider outage, and a
user who chooses a Google-free or fully sovereign build.

A simple `push_id -> native token` RAM map is not viable: after a gateway restart
sleeping devices cannot wake to recreate the mapping. A stable push id shared
with every contact also gives any one contact an indefinitely reusable wake
capability and prevents targeted revocation.

## Decision

### 1. Wake follows durable sealed delivery

A sender requests a wake only after one of these events:

1. the recipient directly acknowledged the sealed envelope at the transport
   layer but an end-to-end delivery receipt has not yet arrived; or
2. a recipient-selected mailbox relay acknowledged durable acceptance of the
   sealed envelope.

The first version normally emits for case 2, where waking the recipient can
immediately collect useful work. A wake is never emitted before the envelope is
queued or merely because a user is typing. Group fan-out evaluates this rule per
member and coalesces multiple accepted messages for the same native destination.

APNs/FCM acceptance, native delivery, application launch, and mailbox collection
do not advance `queued`, `sent`, or `delivered`. Existing encrypted receipts
remain authoritative. Failure to wake leaves the envelope in the ordinary
mailbox/direct retry path.

### 2. The gateway issues opaque, per-contact wake capabilities

When a user enables native wake, the application obtains the current APNs or FCM
registration token and sends it over authenticated TLS to its configured wake
gateway. The gateway returns a distinct capability for each contact direction:

```text
capability_plaintext =
    version(1) || platform(1) || environment(1) || flags(1) ||
    expires_at(8) || capability_id(16) || token_len(2) || token ||
    topic_len(1) || app_topic || zero_pad_to_profile

wake_cap = key_id(4) || nonce(24) ||
           XChaCha20-Poly1305.Seal(
               gateway_key[key_id],
               nonce,
               capability_plaintext,
               "Komms-Wake-Capability-v1"
           )
```

Capabilities use one fixed public size profile, contain at least 128 bits of
random `capability_id`, expire within 30 days, and are refreshed on native-token
change, application launch, and while the app is active near expiry. Current and
immediately previous capabilities may overlap during rotation. The device sends
each contact's capability only inside their existing authenticated ratchet and
deletes it on block/contact removal.

The gateway does not need a durable `push_id -> token` map to open a capability.
Gateway encryption keys are durable, versioned, non-exportable where platform
support permits, held in an HSM/KMS boundary, and rotated with an overlap at
least as long as the capability lifetime. A bounded revocation entry keyed by
`capability_id` may persist only until that capability expires; revocation
state contains no native token. If an operator instead uses a mapping store, the
mapping is encrypted at rest under an equivalent non-exportable key and follows
the same expiry and logging rules.

Possession of `wake_cap` is the authorization to request a wake. Per-contact
capabilities limit revocation and abuse impact but do not hide from the gateway
that different capabilities ultimately open to the same provider token. A
gateway compromise can open unexpired capabilities it observes and correlate
destinations; ADR-0017 records this residual.

### 3. Trigger requests are fixed, replay-bounded, and coalesced

The production endpoint uses a bounded binary body:

```text
POST /v1/wake/trigger
Content-Type: application/komms-wake-v1

version(1) || wake_cap_len(2) || wake_cap || request_nonce(16) || zero_pad
```

The complete request and response have fixed size profiles. The response is
always a generic 202 for a syntactically valid request, whether the capability
opened, expired, was revoked, was rate-limited, or the native provider refused
it. `request_nonce` is random and retained only in a short bounded replay cache
keyed by capability id; it is not sender authentication and is never logged.

The gateway enforces concurrent-request, body-size, bandwidth, per-capability,
per-native-destination, and global provider quotas. Ticks for one native token
are collapsed within a short operator-configured window, and APNs/FCM collapse
identifiers replace older pending ticks. Over-limit or duplicate requests are
silently coalesced rather than creating an oracle. An authorized contact can
still spend its own capability's bounded wake budget; blocking/revocation and
expiry end that ability.

In Private mode the same body is encapsulated through Oblivious HTTP or sent
through Tor. The OHTTP relay and gateway must be operated by non-colluding
administrative domains, use HTTPS on both legs, strip connection metadata, and
add no client identifier, cookie, or stable request header. Standard mode sends
the fixed body directly over HTTPS.

### 4. Native payloads contain no conversation data

The gateway never receives or sends sender identity, recipient Komms identity,
conversation/group id, message id, type, text, media metadata, unread count,
timestamp, or cryptographic session material. The recipient chooses one of two
static APNs profiles when it issues a capability:

Background-only:

```json
{"aps":{"content-available":1}}
```

Generic visible alert:

```json
{"aps":{"alert":{"title":"Komms","body":"New activity"},"sound":"default","content-available":1}}
```

The background profile uses `apns-push-type: background` and priority 5. The
generic profile uses `apns-push-type: alert` and the platform-supported alert
priority. Both use a destination-scoped collapse id, and neither varies by
contact or message. The generic alert is the Standard-mode reliability option:
it may notify the user even when iOS declines to launch the app, at the cost of
revealing to Apple and an observer that Komms displayed a generic notification.
Background-only delivery is low-priority, may be delayed or discarded, and does
not launch an application the user force-quit. When either profile grants
background execution, the handler performs one bounded collection pass within
the operating-system budget, reports completion, and leaves remaining work
durable for foreground or a later opportunity.

On Google Play Android, urgent high-priority FCM is used only when Komms can
immediately display a generic user-visible notification such as “New Komms
activity”; repeated invisible high-priority data messages are forbidden because
FCM may deprioritize them. The generic text is static and contains no sender or
message data. Collection beyond the short callback is scheduled through an
expedited WorkManager job when permitted. Normal-priority data messages and
ordinary WorkManager are the fallback when the user has disabled visible
notifications or the event is not urgent.

The Google-free Android flavor contains no FCM SDK and ignores FCM capability
advertisement. Apple builds use APNs directly rather than routing Apple delivery
through FCM. PushKit/VoIP pushes are reserved for genuine incoming calls under
the platform call contract and are not a generic message wake mechanism.

### 5. Receipt-side work is bounded and uses existing paths

On a valid native wake the application asks `kult-node` to run a coalesced wake
collection cycle:

1. check already configured recipient-selected mailbox relays until the
   per-wake envelope/count/byte budget is reached;
2. refresh expired rendezvous hints only for peers with relevant pending work;
3. feed collected sealed envelopes through the ordinary receive, deduplication,
   ratchet, persistence, notification, and receipt paths; and
4. stop at the platform deadline, leaving all remaining work durable.

The native payload never selects a contact or route. A malicious or duplicate
wake therefore triggers only the same bounded generic collection that normal
node operation performs. Mesh flooding, sneakernet export, attachment autoplay,
and call setup never start solely because of a wake.

Wake capabilities, native-token state, revocations, and retry/coalescing state
are sealed core service state. F5 stores only the user's mode, notification, and
provider preferences. B8 scheduled messages do not activate early to create a
wake, and a pending wake is not represented as a scheduled chat message.

### 6. Logging and provider errors are minimized

Native tokens and wake capabilities are treated as sensitive pseudonymous
identifiers. They do not enter access logs, analytics, traces, crash payloads,
support dashboards, or request/error bodies. Provider responses are reduced to
bounded aggregate counts by platform and error class. Invalid/unregistered-token
responses cause the corresponding opened capability or encrypted mapping to be
retired without retaining the token in an error queue.

Operator health metrics cover queue depth, latency, coalescing, provider status,
and aggregate success/error classes. They never include a capability id, token,
full client address, app-generated contact id, or per-user time series.

## Alternatives considered

### Stable hashed `push_id` mapped to a native token in RAM

Rejected. Hashing does not hide the target from the server that holds the map,
all contacts share one irrevocable capability, and a restart loses the ability
to wake devices that must wake in order to register again.

### Put encrypted message data or a sender hint in the native payload

Rejected. It would create a provider-carried message path, increase metadata
and payload parsing, and let notification behavior become an oracle. The native
payload is static.

### Treat a silent push as guaranteed delivery

Rejected. Both mobile platforms schedule, throttle, delay, or drop background
work; iOS force-quit and Android Doze/OEM policy are explicit failure cases.

### Allow arbitrary self-hosted gateways to use official app credentials

Rejected. APNs keys and FCM service credentials authorize the official app and
cannot be safely distributed. Federation occurs at rendezvous and anonymizing
ingress; custom application builds use their own provider credentials.

### Use VoIP push for all messages on iOS

Rejected. It violates the platform contract, expands permissions and review
risk, and would make ordinary messages masquerade as calls.

## Consequences

- Ordinary users can receive timely generic notification and collection hints
  while message content remains on Komms transports.
- Wake reliability remains lower than a centralized messenger that stores
  provider-visible account state and controls the whole delivery path; the UI
  and tests must be honest about this limit.
- The official distribution operates security-critical native-provider
  credentials and durable gateway encryption keys even though it never receives
  message keys or plaintext.
- Blocking a contact rotates or revokes its wake capability without changing
  the Komms identity or other contacts' capabilities.
- Real-device acceptance must cover APNs throttling and force-quit, Background
  App Refresh off, token rotation, FCM Doze/deprioritization, notification
  permission denial, provider outage, replay, flood, and gateway restart.
