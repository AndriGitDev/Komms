# 43: Field qualification

**Status:** runnable matrix published; physical and real-network rows open

Field qualification is evidence about an exact application artifact on an
exact physical system and network. It is not another name for a unit test,
Simulator launch, local network namespace, or successful build. The canonical
inventory is
[`field-qualification/v1/matrix.json`](../field-qualification/v1/matrix.json);
the bounded record validator is
[`scripts/field-qualification.py`](../scripts/field-qualification.py).

The matrix covers the P0-04 and P0-09 release surface: clean installation,
first contact, message requests and group-invite consent, offline mailbox
delivery, recovery and linked-device loss, attachments and calls, screen
security, accessibility, mobile lifecycle, Wi-Fi/cellular handoff, ordinary
NAT/IPv6/CGNAT/hole-punch/relay conditions, optional-service failure, operator
replacement, pure-core operation, and the physical Meshtastic bench.

No stable support cell is implied by appearing in the target inventory. A cell
becomes supported only when every applicable row is `pass` on the exact
revision and artifact and the release evidence ledger accepts that evidence.

## 1. Evidence levels

The record format permits six states:

| State | Meaning |
|---|---|
| `open` | No run has been claimed. The combination remains unsupported. |
| `blocked` | The exact hardware, account, network, credential, or external condition is stated but unavailable. |
| `observed` | A real run produced useful development evidence outside the row's qualifying environment. It closes no field claim. |
| `simulator-pass` | Every applicable step passed in an emulator or Simulator. It is implementation evidence only. |
| `pass` | Every step passed on one matrix-authorized physical host/device, network pair, or HIL bench. |
| `fail` | At least one executed step failed; the record includes a retest disposition. |

The validator rejects:

- `pass` on any emulator or Simulator target;
- `simulator-pass` for a physical-only scenario such as cellular handoff,
  APNs/FCM behavior, real audio routing, real NAT traversal, or RF;
- a result that omits a canonical row or procedure step;
- a result not bound to an artifact digest and full source revision;
- missing per-step duration/observation or missing redacted evidence;
- evidence whose bytes no longer match its digest; and
- fields for provider tokens, capabilities, phrases, private keys, message
  content, contact graphs, safety numbers, device serials, or subscriber
  identifiers.

`blocked` is not green or red product evidence. It is an honest open gate.
Local release checks are green when this mechanism and its regression tests
pass; stable release readiness additionally requires the applicable physical
rows themselves to pass.

## 2. Target inventory

The initial target set deliberately includes available local development
environments and named physical release candidates:

| Target | Current availability | Maximum evidence level now |
|---|---|---|
| MacBook Air (M1, 2020), macOS 26.5.2 (25F84), arm64 | Available physical host | `pass` for actually exercised macOS rows |
| Mac mini (2018), current macOS 15 security release, x86-64 | Hardware not present | `blocked` |
| Dell Latitude 5440, Windows 11 24H2, x86-64 | Hardware not present | `blocked` |
| Dell Latitude 5440, Ubuntu 24.04 LTS / GNOME Wayland / ext4 | Hardware not present | `blocked` |
| Google Pixel 8, stock Android 15 | Hardware not present | `blocked` |
| Samsung Galaxy S24, stock Android 15 | Hardware not present | `blocked` |
| iPhone 15, current iOS 26.5 security release | Hardware not present | `blocked` |
| iPhone SE (3rd generation), current iOS 26.5 security release | Hardware not present | `blocked` |
| `sdk_gphone64_arm64` API 35 / Android 15 emulator | Available | `simulator-pass` |
| iPhone 17 Pro and iPhone 17e, iOS 26.5 Simulator | Available | `simulator-pass` |
| Two physical clients on separately administered ordinary NATs | Network and endpoints not assigned | `blocked` |
| Physical CGNAT/IPv6 network pair | Carrier/network and endpoints not assigned | `blocked` |
| Two endpoint stock Meshtastic radios plus stock repeater | Radios not attached | `blocked` |

The named model/OS cells are a bounded test target, not a purchasing
recommendation or a support statement. If a physical run uses a different
model or current security build, change the matrix through review before
claiming that cell. Do not overwrite the identity in a retained record.

## 3. Create a run

Commit the source first and build the exact artifact. A run refuses tracked
worktree changes when it obtains the revision itself. Create one record per
target:

```sh
python3 scripts/field-qualification.py new \
  --cell android-api35-arm64-emulator \
  --artifact application=apps/android/app/build/outputs/apk/googleFree/debug/app-googleFree-debug.apk \
  --network "host-only emulator network" \
  --output target/field/android-api35.json
```

Use additional `--artifact role=path` arguments for an XCFramework, gateway
image, mailbox image, prior-version installer, or another exact input used by
the run. The record stores only each basename, byte count, and SHA-256—not an
absolute local path.

For a network pair, override the generic target descriptions with exact
endpoints:

```sh
python3 scripts/field-qualification.py new \
  --cell distinct-ordinary-nat-pair \
  --device "endpoint A model; endpoint B model" \
  --os-version "endpoint A build; endpoint B build" \
  --architecture "endpoint A architecture; endpoint B architecture" \
  --network "separately administered IPv4 NAT classes and providers" \
  --carrier "provider names only; no account or subscriber identifiers" \
  --artifact endpoint-a=path/to/artifact-a \
  --artifact endpoint-b=path/to/artifact-b \
  --output target/field/distinct-nat.json
```

Use throwaway identities and synthetic content. For every executed row, fill:

- `started_at` and `ended_at` as second-precision UTC;
- the exact artifact digest or digests used by that row;
- each canonical step's `status`, `duration_ms`, and bounded observation;
- one aggregate row observation;
- paths, byte counts, SHA-256 digests, and descriptions for redacted evidence;
- `redaction_reviewed: true`; and
- a retest disposition for every `fail`, or exact unavailability for every
  `blocked`.

Evidence paths are normalized relative paths beneath the record directory.
Retained screenshots must use synthetic conversations. Logs must be reduced to
the minimum needed and reviewed for paths, IP addresses, device identifiers,
provider tokens, message bytes, contact identifiers, and per-user timelines.

Validate without weakening the evidence boundary:

```sh
python3 scripts/field-qualification.py validate \
  --record target/field/android-api35.json
```

`--skip-evidence-files` exists only to inspect a detached metadata copy. It is
not accepted for a release record. `--require-qualified-complete` rejects every
state other than `pass` and is therefore never appropriate for a Simulator.

## 4. Revision-wide summary

After runs for one exact candidate revision are retained, produce a canonical
summary:

```sh
python3 scripts/field-qualification.py summarize \
  --expected-revision FULL_COMMIT_ID \
  --record path/to/first-run.json \
  --record path/to/second-run.json \
  --output path/to/field-summary.json
```

The summary rejects mixed revisions and duplicate target cells. A target is
`qualified: true` only when every applicable scenario is `pass`. Missing
records and omitted scenarios become `open`; a simulator never becomes
qualified. The stable-beta record must be regenerated for the final candidate
revision rather than carrying a pass forward from older source.

## 5. Mobile execution

Android and iOS physical runs use the shared matrix plus the more detailed
[native-wake qualification procedure](38-native-wake-mobile-qualification.md).
At minimum:

1. clean-install the exact Play/Google-free or iOS artifact;
2. exercise first contact, requests, groups, mailbox delivery, recovery,
   attachments, screen protection, and every accessibility row;
3. background/lock, force-stop or force-quit, deny/restore notifications, and
   hand off between real Wi-Fi and cellular;
4. on Android, record Doze, OEM behavior, provider delay/deprioritization, and
   the Google-free absence of FCM;
5. on iOS, record Background App Refresh off, APNs profile headers/priorities,
   token rotation, and the absence of PushKit; and
6. blackhole the optional gateway/provider and prove ordinary durable delivery
   and authenticated receipts retain their meaning.

Provider acceptance is never `sent` or `delivered`. A wake that starts a
collection pass is not message delivery. Simulator UI/permission observations
remain `simulator-pass` even when visually perfect.

## 6. Real-network execution

Do not use two namespaces, two processes on one laptop, a loopback relay, or a
single home router as the distinct-NAT result. Retain only secret-free route
class and timing evidence, but record enough conditions to reproduce the run:

- endpoint model, OS/build, architecture, artifact digest, and whether it was
  on Wi-Fi, Ethernet, or cellular;
- separately administered providers, NAT class, real IPv4/IPv6 availability,
  and CGNAT confirmation where applicable;
- bootstrap, mailbox, relay, rendezvous, and wake operator roles by public
  service identity/digest, never capability or user token;
- first-contact, first-message, offline-delivery, fallback, call, and handoff
  timings;
- exact injected blackholes/restarts/overload; and
- failure and retest disposition.

Run the default-domain blackhole, alternate bootstrap, replacement operator,
and pure-core/self-hosted journeys separately. Success in one does not infer
the others.

## 7. Meshtastic HIL

The physical radio procedure is
[the HIL bench runbook](10-hil-bench.md). The serial real-radio tests now emit:

- `KOMMS_HIL_RESULT` for isolated two-endpoint E2EE; and
- `KOMMS_HIL_BRIDGE_RESULT` for the real-RF plus local-QUIC bridge path.

Both are content-free aggregate JSON: radio-reported region and modem
parameters, frames handed and received, envelope-byte counts, estimated
airtime, pre-transmission duty refusals, decoded envelope count, malformed
private-port count, and elapsed time. They contain no serial path, radio node
number, delivery token, peer, ciphertext, or message identifier.

The base bench needs two stock-firmware endpoint radios. Isolated multi-hop
adds a stock repeater and physical attenuation/separation proving the endpoints
cannot hear one another directly. The Internet-bridge field row additionally
needs a separately reachable network endpoint; the local-QUIC bridge HIL result
alone is useful `observed` evidence, not that stronger pass.

## 8. Current support boundary

At publication of this matrix there is no retained complete physical Android,
iOS, Intel macOS, Windows, Linux, distinct-NAT, CGNAT, or Meshtastic run for the
current source. Those cells remain unsupported and P0-04/P0-09 remain open.
The available simulators are intentionally useful for implementation checks,
but they cannot exercise radio hardware, physical battery/thermal behavior,
real APNs/FCM delivery, OEM scheduling, cellular handoff, audio routing,
biometrics, real NATs, or device-specific accessibility.

Closing the field gate requires genuine runs, not changing these labels.
