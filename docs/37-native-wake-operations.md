# 37: Native-wake gateway operations

The standalone `kult-wake` service implements the least-authority gateway in
[ADR-0019](adr/0019-native-wake-gateway.md). It has one role: open a fixed-size
opaque capability, apply bounded replay/revocation/rate/coalescing policy, and
ask APNs or FCM to send one static content-free notification profile.

It is not a message transport, mailbox, Komms endpoint, account directory,
rendezvous service, updater, analytics system, or plaintext bridge. Its API has
no sender, Komms account, conversation, message, text, media, unread-count, or
timestamp field. A valid gateway response means only that the fixed-shape
request was processed; it never means registered, reachable, sent, received, or
delivered.

This is still an observable service. Direct ingress exposes source network
addresses, timing, volume, and availability to the operator and hosting
provider. Opening a capability reveals the APNs/FCM token, application topic,
static profile, and expiry to the running gateway. The gateway can correlate
different capabilities that open to one native destination. An administrator
can change the software, inspect memory, log future requests, suppress wakes,
or interfere with native-provider traffic. Fixed shapes, minimized state, and
disabled logs reduce retained data; they do not make the operator unable to
observe or interfere.

## 1. Build and artifact identity

The dedicated Dockerfile builds only `kult-wake` from the locked workspace and
embeds the complete source revision:

```sh
docker build \
  --file deploy/wake-gateway/Dockerfile \
  --build-arg KOMMS_SOURCE_REVISION="$(git rev-parse HEAD)" \
  --build-arg SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)" \
  --tag komms-wake:local \
  .
```

On a clean Linux checkout, create the revision-bound binary evidence bundle:

```sh
deploy/wake-gateway/build-artifact.sh "$(git rev-parse HEAD)"
```

The bundle contains the stripped binary, SHA-256 manifest, normalized tar
archive, source revision/date, target triple, compiler version, and locked-build
statement. A second controlled environment must reproduce and compare it before
any reproducibility claim is made. Container publication, SBOM/provenance
retention, and signing remain part of the production release-engineering gate;
do not deploy or advertise a moving local tag.

The runtime image contains the dedicated binary on a read-only Debian root and
runs as numeric uid/gid `10003`. It does not contain `kultd`, endpoint state, a
shell entrypoint, or a user identity key.

## 2. Keep every credential role separate

The gateway has four independent credential classes:

1. a TLS 1.3 private key and certificate for the public fixed-shape listener;
2. one or more versioned capability-encryption keys;
3. an APNs signing key and/or FCM service account; and
4. a deliberately selected CA bundle for outbound APNs/FCM TLS.

None may be a Komms account, device, recovery, mailbox, rendezvous, provider-
directory, or software-release key. APNs and FCM credentials are native-provider
authority for named official application topics; they are never distributed to
third-party operators. A custom application build uses its own provider
credentials and topics.

Generate one owner-only file-backed capability key for a local or bounded
deployment profile:

```sh
install -d -m 0700 -o 10003 -g 10003 /etc/komms-wake/service-keys
kult-wake generate-capability-key \
  --output /etc/komms-wake/service-keys/capability-1.key \
  --key-id 1
chmod 0600 /etc/komms-wake/service-keys/capability-1.key
```

The core key-provider interface admits an HSM/KMS-backed implementation. The
committed standalone binary currently loads bounded owner-only regular files;
using that file profile is not evidence that a key is non-exportable. Production
enrollment at an HSM/KMS or native-provider credential boundary requires an
explicit human-controlled procedure and must not put secret material in the
repository, image, environment, logs, issue tracker, or support transcript.

TLS private keys, APNs `.p8` keys, FCM service-account JSON, and capability keys
must be regular non-symlink files with no group/world permissions. The TLS
certificate and outbound CA bundle may be public. Configuration rejects reused
paths across roles.

Inspect only non-secret fingerprints after all files are mounted:

```sh
kult-wake check --config /etc/komms-wake/config.toml
kult-wake inspect --config /etc/komms-wake/config.toml
```

Inspection prints the TLS leaf SHA-256, active capability-key id, and the id and
SHA-256 fingerprint of each loaded capability key. It never prints private-key
or provider-token bytes.

## 3. Durable state and the no-stale-restore rule

`state.db` contains only bounded capability-id revocations and request replay
nonces with expiry. It contains no APNs/FCM token, Komms identity, message
ciphertext, or social label. The database must nevertheless remain durable
across ordinary process/container restart: losing a revocation row while its
capability key remains active can make a formerly revoked capability usable
until expiry.

Mount one dedicated owner-only state directory at `/var/lib/komms-wake`. Do not
put it in a user `KKR10` backup. Do not take live snapshots or restore a stale
copy. If the state database is lost, rolled back, corrupt, or restored from an
uncertain point, immediately disable every capability-key version that was
active during the uncertain interval, generate a new key id, and require
clients to register and redistribute fresh capabilities. Restoring old
capability keys without the exact current revocation state is unsafe.

Replay rows and revocation rows expire transactionally and are capped
independently. SQLite uses full synchronization and WAL protection; a process
restart retains committed rows. A generic revoke is possession-authorized and
idempotent. Revocation state lasts no longer than the capability itself.

## 4. Host and container boundary

Before starting the service:

1. dedicate a host/VM or a strongly separated service account to native wake;
2. disable swap, hibernation, core dumps, provider snapshots, and crash-memory
   capture;
3. do not place an access-logging proxy, CDN, WAF, TLS terminator, profiler, or
   distributed tracing collector in front of the listener;
4. terminate public TLS in `kult-wake`;
5. restrict administrative access and native-provider credential access;
6. expose only public TCP port `8444`; keep aggregate health on loopback
   `127.0.0.1:8082`; and
7. record the hosting provider, administrative domain, source revision, image
   digest, key fingerprints, enabled native providers, limits, uptime, and
   incidents in the operator record.

The committed Compose profile adds:

- read-only root filesystem and numeric unprivileged user;
- all Linux capabilities dropped and `no-new-privileges`;
- bounded CPU, 384 MiB memory with no additional swap, 128 processes, file
  descriptors, and zero core ulimit;
- `noexec,nosuid,nodev` tmpfs for transient runtime paths;
- separate read-only mounts for service keys, native credentials, and CA roots;
- a dedicated durable state mount; and
- Docker logging driver `none`.

The process emits one content-free startup line containing only the TLS
fingerprint, active capability-key id, and source revision. With the committed
deployment profile that line is not retained by the container runtime.

## 5. Configure and start

Copy the strict version-1 example and replace every placeholder:

```sh
install -d -m 0755 /opt/komms-wake
install -m 0644 deploy/wake-gateway/wake-gateway.toml \
  /opt/komms-wake/config.toml
export WAKE_GATEWAY_IMAGE='registry.example/komms-wake@sha256:<digest>'
export WAKE_GATEWAY_CONFIG=/opt/komms-wake/config.toml
export WAKE_SERVICE_KEYS_DIR=/etc/komms-wake/service-keys
export WAKE_NATIVE_CREDENTIALS_DIR=/etc/komms-wake/native-credentials
export WAKE_PROVIDER_CA_FILE=/etc/komms-wake/provider-roots.pem
export WAKE_STATE_DIR=/var/lib/komms-wake
docker compose -f deploy/wake-gateway/compose.yaml config --quiet
docker compose -f deploy/wake-gateway/compose.yaml up -d --wait
```

Configuration is `deny_unknown_fields`; an unknown key, relative/reused path,
non-loopback health address, inconsistent rate hierarchy, missing provider,
unsafe timeout relationship, invalid topic, or out-of-range resource bound
fails startup.

The committed example defaults are:

| Axis | Bound |
|---|---:|
| Capability lifetime | 30 days |
| Public TLS connections | 256 concurrent |
| Connections | 30,000/minute global; 120/minute per exact source |
| Source-rate buckets | 65,536 |
| Request / provider deadline | 15 / 11 seconds |
| Capability triggers | 6/minute |
| One native destination | 12/minute |
| Whole native-provider plane | 10,000/minute |
| Capability/destination quota buckets | 65,536 each |
| Coalescing interval | 30 seconds |
| Durable revocations / replay nonces | 200,000 / 500,000 |
| Native-provider response | 16 KiB |
| Graceful shutdown | 10 seconds |

Every public register, trigger, revoke, generic response, and malformed response
uses its one fixed binary shape. Public capability material never appears in a
URL. The public server accepts TLS 1.3 and one bounded canonical HTTP/1.1
request per connection. APNs/FCM adapters use TLS 1.3 HTTP/2 to fixed official
provider hosts; configuration cannot redirect credentials to another host.

## 6. Health, overload, restart, and smoke checks

The loopback health endpoint reports only aggregate counters: source revision,
durable revocation/replay row counts, issued/refused registrations, malformed/
invalid/expired/revoked/replayed/coalesced/rate-limited requests, reduced
provider outcome classes, and accepted revocations. It exposes no token,
capability id, nonce, address, topic, app identity, or per-user timeline.

```sh
docker compose -f deploy/wake-gateway/compose.yaml exec -T wake-gateway \
  kult-wake probe --address 127.0.0.1:8082
```

Run the committed profile smoke against every candidate immutable image:

```sh
WAKE_GATEWAY_IMAGE='registry.example/komms-wake@sha256:<digest>' \
  deploy/wake-gateway/smoke-test.sh
```

It validates Compose, creates temporary non-production credentials, starts the
service, probes aggregate health, restarts, probes again, and verifies the
disabled Docker log driver. Rust tests separately cover fixed shapes, malformed
requests, replay, flood, quota/coalescing behavior, key overlap, revocation,
restart, provider error reduction, provider outage, and a deadline-bounded
blackhole.

Overload is a generic refusal/coalescing outcome. Registration refusal,
invalid/expired/revoked capability, replay, quota, provider refusal, and
provider outage must not become a response oracle. APNs/FCM acceptance remains
best effort and never changes core message state.

## 7. Rotation, revocation, and compromise

### Capability-encryption key

Generate a new non-zero id, add both old and new files, make the new id active,
run `check`/`inspect`, then restart. Keep an uncompromised previous key loaded
until every capability it issued has expired (at most 30 days). Clients
register fresh per-contact capabilities and distribute complete monotonic sets
through authenticated pairwise sessions. Their durable identity-free revoke
queue retries superseded capabilities without changing message state.

On compromise, disable the affected key immediately rather than preserving an
overlap. Every capability under it becomes unusable; clients fall back to
ordinary mailbox/direct delivery and register again.

### TLS key/certificate

Move to a parallel origin or explicitly authenticated new leaf pin. Distribute
the new origin/pin through signed provider configuration and authenticated
contact controls before removing the old one. A certificate change without the
corresponding pin update fails closed.

### APNs/FCM credential

Revoke it at Apple/Google, enroll a distinct replacement, and verify only the
declared application topics. Do not solve an incident by copying official
credentials to another operator or reusing a directory/release key. Provider
credential compromise can send static notifications to known tokens; it does
not grant Komms message or identity authority.

### Host or state compromise

Remove the operator from defaults, stop the gateway, revoke native-provider
credentials as needed, disable every uncertain capability key, rebuild from a
reviewed immutable digest, start with a fresh state epoch and key id, and
publish the timing and metadata risk. Do not retain request/body captures or
memory dumps as routine diagnostics.

## 8. Self-hosting, replacement, and deployment status

An operator of a custom app can deploy the same gateway with its own native
provider credentials, service keys, topics, domain, limits, and public record.
Official-app provider credentials are not shared. Standard mode may use a
disclosed replaceable direct gateway. Private mode requires Tor or correctly
separated OHTTP ingress and cannot claim non-collusion without distinct
administrative domains. Sovereign and Google-free builds advertise no native
wake capability.

An operator leaving service stops new registrations, publishes an end date and
replacement if one exists, overlaps the replacement for the declared
capability lifetime where safe, then disables its capability and provider
keys. Loss of wake convenience must leave direct, DHT, mailbox, LAN, mesh, and
sneakernet delivery intact.

No native-wake gateway was deployed while preparing these artifacts. No
production APNs/FCM credential, public domain, provider-directory entry, image
digest, host, or operator was authorized. The remaining deployment action is:
after an exact target, administrative domain, immutable image/config digest,
service/native key fingerprints, data-flow disclosure, and rollback plan are
shown and explicitly authorized, apply the validated profile and complete the
[operator record](wake-gateway-operator.md).
