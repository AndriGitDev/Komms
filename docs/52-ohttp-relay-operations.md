# 52: Oblivious HTTP Relay Operations

`kult-ohttp-relay` is the least-authority
[RFC 9458](https://www.rfc-editor.org/rfc/rfc9458.html) relay-side artifact for an
optional Private-mode ingress. One process exposes one public Oblivious Relay
Resource and forwards its encrypted body to exactly one configured Oblivious Gateway Resource
over HTTPS. It has no OHTTP gateway HPKE private key and cannot decapsulate a
valid request or response.

The artifact is implemented locally, but no project OHTTP relay or gateway is
deployed. Komms clients still use the explicit loopback Tor path for the
implemented Private mode. A relay image by itself is not an end-to-end OHTTP
path, non-collusion evidence, anonymity evidence, or operator qualification.

## 1. Fixed least-authority boundary

The service accepts only:

```text
POST /ohttp HTTP/1.1
Host: configured-public-authority
Content-Type: message/ohttp-req
Content-Length: configured-exact-size
```

The public resource, exact encapsulated request and response sizes, gateway
network target, TLS server name, port, and gateway resource are all fixed in
strict versioned configuration. Query strings and fragments are rejected, so
client input can never select a destination or turn the process into a generic
proxy.

For each accepted request the relay constructs a new upstream request
containing only `Host`, `Content-Type`, `Content-Length`, and `Connection:
close`. It copies the encrypted body verbatim. It never forwards `Forwarded`,
`Via`, `X-Forwarded-For`, client authorization, cookies, user agent, connection
metadata, or any unknown client header. Both hops require TLS 1.3. The gateway
CA bundle is explicit and read-only; no ambient system trust or redirect is
used.

Only a `200` response with `message/ohttp-res`, the exact configured body
length, bounded headers, and no transfer/content encoding is returned as a
success. All gateway, TLS, timeout, malformed-response, and non-200 outcomes
become the same empty `502`. Malformed client requests become the same empty
`400`. The relay never automatically retries: an interrupted HTTP/1.1 exchange
does not prove that the gateway skipped the request.

These choices implement the RFC 9458 relay responsibility to copy
encapsulated request/response content while withholding source metadata. The
target application and gateway remain responsible for replay safety. Fixed
outer sizes are a Komms deployment profile, not a general claim about every
possible OHTTP application.

## 2. Data, authority, and retention

The relay holds only:

- one dedicated public TLS certificate/private key;
- one pinned gateway CA bundle;
- the fixed public-to-gateway mapping and resource limits; and
- a random in-memory key for one-minute source-rate buckets.

It must never receive a user account or recovery key, message key or plaintext,
gateway HPKE private key, provider-directory or release-signing key, contact
label, native push token, target capability in a URL, or client identifier to
forward. The encrypted OHTTP body exists only for the bounded live exchange.
There is no database, queue, request cache, replay store, backup, snapshot, or
application log.

The relay operator and hosting/network providers can still observe client
network addresses at relay ingress, the configured gateway destination,
timing, volume, fixed request/response sizes, TLS metadata, refusal outcomes,
and availability. The gateway decapsulates OHTTP and can see the protected
target method, URI, headers, and body; the Komms target profile must keep that
body least-authority and fixed-shape. A host administrator can inspect memory,
change the binary, enable logging, suppress traffic, or cooperate with the
gateway. OHTTP does not protect against relay/gateway collusion or a
sufficiently capable traffic observer.

## 3. Bounded admission and aggregate health

The committed profile bounds concurrent TLS tasks, global and per-source
requests per minute, total reserved request-plus-response bytes per minute,
volatile source buckets, header bytes, exact body bytes, TLS handshake time,
complete request time, gateway time, and shutdown grace. Source addresses are
keyed into volatile one-minute buckets and are never emitted. Source-specific
limiting is differential treatment and can reduce an anonymity set; it is a
documented availability control, not an identity or Sybil claim.

The loopback-only health endpoint reports aggregate counters for accepted,
overloaded, TLS-failed, malformed, forwarded, successful, and gateway-failed
operations plus the bounded source revision. It contains no addresses,
headers, bodies, mapping values, certificates, or per-client traces.
`status: ready` means the local listeners and configuration are usable; it is
not a probe or promise of gateway reachability.

## 4. Hardened deployment

The deployment profile is:

- [`deploy/ohttp-relay/Dockerfile`](../deploy/ohttp-relay/Dockerfile);
- [`compose.yaml`](../deploy/ohttp-relay/compose.yaml); and
- [`ohttp-relay.toml`](../deploy/ohttp-relay/ohttp-relay.toml).

It builds only `kult-ohttp-relay` from the locked workspace, runs as UID/GID
`10004`, drops every Linux capability, enables `no-new-privileges`, uses a
read-only root, disables swap growth, core dumps, and the container log driver,
and mounts no persistent mutable volume. Writable paths are bounded tmpfs. Do
not place it behind a CDN, WAF, logging reverse proxy, or separate TLS
terminator.

Build a local validation image without publishing:

```sh
docker buildx build \
  --file deploy/ohttp-relay/Dockerfile \
  --tag ghcr.io/andrigitdev/komms-ohttp-relay:ohttp-relay-ci \
  --load .
KOMMS_OHTTP_RELAY_IMAGE=ghcr.io/andrigitdev/komms-ohttp-relay:ohttp-relay-ci \
  deploy/ohttp-relay/smoke-test.sh
```

The standalone reproducible archive path is Linux-only, requires a clean exact
revision, and refuses to replace an existing destination:

```sh
deploy/ohttp-relay/build-artifact.sh "$(git rev-parse HEAD)"
```

One process represents one fixed mapping. Operate a second mapping as a
separate process, address, TLS key, configuration, capacity pool, and operator
record. Never add an arbitrary target header, URL parameter, CONNECT method,
or shared gateway-key mount.

## 5. Configuration and key lifecycle

Before operation:

1. generate a dedicated relay TLS key through the operator's normal protected
   enrollment process and keep it owner-only;
2. obtain the exact gateway CA or private trust anchor through an authenticated
   channel;
3. record the relay certificate, gateway CA bundle, and canonical mapping
   fingerprints;
4. choose one exact outer request/response shape supported by the separately
   operated gateway and client profile;
5. bind the public and health listeners and all rate/deadline bounds; and
6. retain the source revision, immutable image digest, configuration digest,
   administrative domain, provider, and source-offer location.

Validate without contacting the gateway:

```sh
kult-ohttp-relay check --config /etc/komms-ohttp/config.toml
kult-ohttp-relay inspect --config /etc/komms-ohttp/config.toml
```

Rotate the public TLS identity with an authenticated overlap and a new
fingerprint. Rotate a gateway CA only after authenticating the gateway change.
Changing the gateway URI, public resource, or body profile creates a new
mapping fingerprint and requires a client/gateway compatibility run. The relay
never generates, stores, rotates, or revokes the gateway's HPKE keys.

On relay-key or host compromise, withdraw that relay URI, revoke/replace its
TLS key, rebuild on reviewed infrastructure, and disclose the address/timing/
volume exposure window. On gateway or CA compromise, stop forwarding, remove
the mapping, and wait for a separately authenticated gateway/key transition.
Neither incident changes Komms identities, delivery truth, or sovereign
fallback routes.

An ordinary upgrade starts the new exact image/configuration beside the old
mapping, validates its fingerprints and real gateway exchange, updates
authenticated provider configuration, and then drains the old process. Because
the relay has no durable application state, rollback selects the prior reviewed
image/configuration/key set unless compromise affected it; it never restores a
request snapshot or retries an interrupted exchange.

## 6. Capacity, cost, and replacement

The default container reserves 256 MiB RAM, one CPU, no persistent disk, and
one public TCP port. Capacity records include connection/request/byte rates,
TLS and gateway failures, peak/p95 CPU and memory, network transfer, uptime,
operator time, and hosting cost. They do not invent a user count from rotating
network sources.

Overload refuses new work before request-body allocation or upstream work and
never retries or advances message state. End of life removes the mapping from
signed/user configuration, keeps the old address only for the disclosed
overlap, and then destroys the retired TLS key. Tor, direct Standard ingress,
mailbox delivery, DHT, LAN, mesh, and sneakernet remain independent.

## 7. Validation and qualification boundary

Local validation is:

```sh
cargo test --package kult-ohttp-relay --all-targets
cargo clippy --package kult-ohttp-relay --all-targets -- -D warnings
deploy/ohttp-relay/smoke-test.sh
python3 scripts/check-stewardship.py
python3 scripts/test-stewardship.py
```

The tests cover strict one-to-one mapping, exact shapes, header stripping,
smuggling rejection, uniform error classes, bounded response parsing,
non-retry construction, rotating source/global admission, aggregate-only
metrics, configuration separation, and hardened container/restart policy.

Private OHTTP qualification remains open until all of the following are
retained against one revision and exact configurations:

- a compatible client and RFC 9458 gateway complete the fixed-shape path;
- relay and gateway are run by named distinct administrative domains with no
  shared host, network control, credential custodian, or logging plane;
- malformed, replay, overload, timeout, blackhole, key rotation, replacement,
  and application-state semantics pass over a real network;
- the provider directory discloses both operators and exact metadata limits;
  and
- independent review dispositions the mapping, header, TLS, and operational
  boundaries.

Local tests and an image are not operator qualification. No non-collusion,
anonymity, deployed-service, or production Private-mode claim is made.
