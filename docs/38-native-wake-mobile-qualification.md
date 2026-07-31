# 38: Native-wake mobile qualification

Android and iOS implement the optional native-wake client in
[ADR-0019](adr/0019-native-wake-gateway.md). This document is the runnable
physical-device gate. Host tests, APK inspection, and Simulator builds exercise
the contract but do not qualify APNs, FCM, operating-system background
execution, battery behavior, or a named device.

No row in this matrix is passed until the exact revision and artifact digest
have run on the named physical device/OS through a real non-production APNs or
FCM project and a revision-bound gateway. Provider tokens, capabilities,
contact identifiers, message content, and per-user timelines must not enter the
evidence archive.

## 1. Implemented client boundary

The iOS app uses APNs directly through `UIApplicationDelegate`; it never links
or calls PushKit. It keeps the current APNs token in process memory, supports
background-only and static-visible profiles, re-registers after launch/token or
relationship changes, revokes when policy becomes ineligible, and runs one
20-second collection pass. Background App Refresh off and force-quit remain
explicit platform limits.

The Android Play flavor alone links Firebase Messaging. High priority is
authorized only by the static visible profile; the background profile is normal
priority. The callback runs one bounded collection pass and schedules one
ordinary WorkManager continuation. Doze, force-stop, OEM restrictions, and FCM
deprioritization remain explicit limits. The Google-free flavor contains no
Firebase, FCM, or Play Services code and advertises no wake capability.

Both shells keep ordinary direct, DHT, mailbox, LAN, mesh, and file delivery
independent of native wake. Standard uses the configured pinned direct gateway.
Private uses only an explicitly configured Tor path; non-colluding OHTTP remains
unqualified. Sovereign configures no wake client.

## 2. Create a revision-bound evidence form

Build the exact artifact first. Then create a form outside the source tree (or
under ignored `target/`) without including provider secrets:

```sh
python3 scripts/native-wake-field-harness.py new \
  --platform android \
  --environment physical \
  --device "manufacturer model / stock build" \
  --os-version "Android version and build" \
  --network "carrier and Wi-Fi/NAT description" \
  --artifact path/to/app-play-release.apk \
  --output target/native-wake/android-run.json
```

Use `--platform ios` with the exact archived `.app` or `.ipa` for Apple. A
Simulator run uses `--environment simulator`; the validator rejects any
simulator row labelled as a physical `pass`.

After each row, record only the result, UTC observation time, and paths to
redacted aggregate metrics/screenshots/log extracts. Validate the completed
form:

```sh
python3 scripts/native-wake-field-harness.py validate \
  target/native-wake/android-run.json
```

The canonical scenario inventory is
[`native-wake-mobile-field-v1.json`](../fixtures/native-wake-mobile-field-v1.json).
Do not remove open or failed rows from a retained result.

## 3. Shared two-user setup

1. Record the source revision, application digest, OS build, device model,
   network/carrier, gateway revision/image digest, and non-secret service-key
   fingerprints.
2. Use two fresh test identities and a real authenticated contact session.
   Configure a non-production gateway with a dedicated APNs/FCM credential and
   an application topic matching the artifact. Never copy a provider token into
   a command, issue, screenshot, or log.
3. Select the background-only profile, then the generic-visible profile. Confirm
   the peer receives a complete new capability generation after each change.
4. Deposit an encrypted message through a durable mailbox while the receiving
   app is backgrounded. Capture message state immediately before the trigger,
   after gateway/provider acceptance, after app collection, and after the
   authenticated receipt.
5. Repeat with the gateway and provider blackholed. Ciphertext and retry state
   must remain durable, and native failure must not relabel delivery.

The only permitted provider payloads are:

```json
{"aps":{"content-available":1}}
{"aps":{"alert":{"title":"Komms","body":"New activity"},"sound":"default","content-available":1}}
{"data":{"wake":"1"}}
{"notification":{"title":"Komms","body":"New activity"},"data":{"wake":"1"}}
```

Any sender, account, conversation, message, text, media, unread-count, or
timestamp field fails the row.

## 4. iOS physical rows

- **Permission denial:** deny notification authorization for the visible
  profile, foreground the app, and confirm the issued set becomes empty.
  Background-only may be selected without alert permission.
- **Token rotation:** reinstall or use the approved APNs sandbox token-rotation
  procedure, then confirm a new complete generation and durable revocation of
  the former capability without recording either token.
- **Background App Refresh off:** disable it in Settings. Background-only must
  become ineligible; ordinary mailbox delivery remains pending until another
  execution opportunity. Restore the setting and verify fresh registration.
- **Force-quit:** swipe the app away, trigger both profiles, and record the
  platform result without calling absence of execution a product failure or
  delivery. Relaunch and verify bounded collection of durable remainder.
- **Headers and collapse:** the gateway-side redacted trace must show
  `apns-push-type: background`/priority `5` for background-only and
  `apns-push-type: alert`/priority `10` for visible, with a destination-scoped
  collapse id and exact static body.

Do not use PushKit or a VoIP entitlement for any row.

## 5. Android physical rows

- **Play versus Google-free:** run the committed APK inspection gate, install
  both artifacts, and confirm only Play offers native wake. Google-free must
  retain ordinary delivery with no Firebase component.
- **Permission denial:** on Android 13+, deny notifications. The visible
  profile must become ineligible and revoke; background-only remains
  normal-priority and best effort.
- **Token rotation:** clear/reinstall through the non-production FCM project or
  use its supported rotation procedure, then confirm a fresh complete
  generation and revocation without capturing the token.
- **Doze/OEM delay:** place the stock device in Doze with the screen off. Normal
  background data may be delayed. The high-priority row must always have the
  static user-visible notification, never an invisible high-priority message.
- **Deprioritization:** exercise the provider test condition or wait for an
  observed downgrade. Komms must leave the durable mailbox/direct path and
  delivery state unchanged.
- **Bounded continuation:** after a wake with more durable work than one pass,
  observe at most the unique ordinary WorkManager continuation. Force-stop must
  leave the documented no-execution condition rather than starting a hidden
  loop or foreground service.

## 6. Gateway and semantic rows

For each platform, replay the exact trigger nonce, exceed per-capability and
per-destination quotas, submit multiple accepted envelopes inside the
coalescing window, restart the gateway with the same current state, revoke the
capability, restart again, and blackhole the native provider. Retain only
aggregate counters and generic response classes.

Pass requires all of the following:

- replay/flood/refusal/outage stay generic and bounded;
- coalescing produces no message-dependent payload variation;
- a revoked capability remains revoked across restart;
- collection activates no mesh flood, sneakernet export, attachment autoplay,
  call setup, or outbound flush;
- provider or gateway acceptance never advances delivery state; and
- ordinary delivery and authenticated receipts still work after every optional
  wake component fails.

Simulator results are useful regression evidence for app launch, UI,
permission-state handling, and static-payload rejection. They remain labelled
`simulator-pass` and cannot close any physical row.
