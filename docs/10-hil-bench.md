# 10: Hardware-in-Loop Bench

The M4 roadmap item "two USB Meshtastic radios in CI-adjacent nightly job"
([09: Implementation Guide §4](09-implementation-guide.md)). This document is the
bench runbook: what to buy, how to prepare the radios, how to register the runner,
and how to arm the nightly.

## What the nightly proves (and what it doesn't need to)

The fake-radio integration tests already pin everything deterministic about the
Meshtastic carrier: the framed client protocol, fragmentation at the 233 B
`Data.payload` cap (a 192-bucket text in ≤ 2 LoRa frames), priority classes,
selective-retransmission NACKs, duty-cycle *arithmetic*, and the full two-daemon
RPC flow (`crates/kultd/tests/mesh_e2e.rs`). None of that gets truer by running
it nightly on a desk.

What only hardware can prove, and what the nightly therefore exercises, is the
real path: USB-serial framing against actual firmware, the radio configuration
handshake (node number, modem params, and the reported region that sizes the
duty-cycle budget), and end-to-end delivery over actual RF, including the
firmware's own queueing and rebroadcast behavior. The carrier also exposes
content-free aggregate counters for frames handed to and received from the
radio, envelope bytes, estimated airtime, pre-transmission duty refusals,
decoded envelopes, and malformed private-port frames.

The test is `crates/kultd/tests/hil.rs`: two `kultd` daemons, each attached to a
real radio, mDNS off, no bootstrap peers. The radios are the only shared medium.
Alice's first message to Bob (carrying the PQXDH handshake, so ~10 frames of
fragments) must arrive and produce a `delivered` receipt back over the air; Bob's
ratcheted reply must round-trip the same way. A second ignored case uses one
endpoint radio and one bridge radio to cross a durable local-QUIC mailbox in
both directions. Timings and aggregate radio counters are printed for the job
log.

The first result is emitted on one line beginning `KOMMS_HIL_RESULT=`. The
mixed bridge result begins `KOMMS_HIL_BRIDGE_RESULT=` and explicitly labels its
scope `physical-rf-plus-local-quic`. Neither line contains serial paths, radio
node numbers, delivery tokens, peer identifiers, ciphertext, or message
identifiers. The second result does not by itself qualify a separately
administered Internet path.

## Hardware

- **Two stock-firmware [Meshtastic](https://meshtastic.org) radios** with USB:
  any supported board works (Heltec V3, RAK4631, LILYGO T-Beam, …). Stock
  firmware is the point: Komms requires no firmware modification (ADR-0005).
- **Antennas attached before anything else.** Transmitting without an antenna
  can destroy the LoRa PA. On one desk, range is irrelevant; the antenna is not.
- **A Linux host** for the runner: a Raspberry Pi is plenty; the job builds the
  workspace, so give it a few GB of disk and either patience or a persistent
  target dir (self-hosted runners keep their work directory between runs, which
  is all the build caching this needs).

## Radio preparation (once, per radio)

With the [Meshtastic CLI](https://meshtastic.org/docs/software/python/cli/)
(`pipx install meshtastic`), for each radio:

```sh
meshtastic --port /dev/ttyUSB0 --set lora.region EU868
```

- **Region**: set the region that is legal where the bench sits. EU868 is the
  region the M4 acceptance names; it is duty-cycle-limited, so the airtime
  budget path runs armed rather than unbudgeted.
- **Modem preset and channel**: leave the defaults (`LongFast`, default primary
  channel) on **both** radios; they must match for the radios to hear each
  other. The channel's own encryption is irrelevant to Komms security (sealed
  envelopes are self-protecting; see [05: Transports §4](05-transports.md)),
  it only determines which mesh rebroadcasts the frames.
- Node names, GPS, telemetry: all irrelevant; defaults are fine.

Sanity-check the pair before blaming Komms for anything: send a text from one
radio to the other with the Meshtastic CLI or app. If stock messaging doesn't
cross the desk, the bench isn't ready.

### Stable device paths

`/dev/ttyUSB0`/`ttyUSB1` ordering changes across replugs and reboots. Use the
by-id paths, which encode the adapter serial number:

```sh
ls /dev/serial/by-id/
```

and put those in the `HIL_SERIAL_A`/`HIL_SERIAL_B` repository variables. The
runner's user needs serial access (`dialout` group on Debian-family systems).

## Runner registration and arming

1. Register a [self-hosted runner](https://docs.github.com/en/actions/hosting-your-own-runners)
   on the repository and give it the extra label **`meshtastic-hil`**.
2. Set repository **variables** (Settings → Secrets and variables → Actions):
   - `HIL_SERIAL_A`, `HIL_SERIAL_B`: the two `/dev/serial/by-id/…` paths.
   - `HIL_BENCH` = `armed`: this is the switch. Until it is set, the nightly
     job skips cleanly instead of queuing forever for a runner that doesn't
     exist; unset it to take the bench down for maintenance without red runs.

The workflow (`.github/workflows/hil-nightly.yml`) then runs nightly and on
manual dispatch:

```sh
cargo test -p kultd --test hil -- --ignored --nocapture --test-threads=1
```

A missing environment variable, an unreachable radio, or a silent mesh all fail
loudly: the test never reports green on a misconfigured bench.

Run the same command by hand (with `KOMMS_HIL_SERIAL_A`/`_B` exported) to use
the bench interactively. The tests share the two serial devices and must remain
single-threaded.

Retain the complete log as a redacted field-evidence file. Before retaining
it, remove host paths, runner names, IP addresses, and serial identifiers;
preserve the exact `KOMMS_HIL_RESULT` lines. Bind that file to the source
revision and application/test artifact with the
[field-qualification form](43-field-qualification.md).

## Security posture

A self-hosted runner executes whatever the workflow tells it to, on hardware you
own. The rules, in force in the workflow and to be kept when editing it:

- **Never add `pull_request` triggers** to any workflow that targets this
  runner: that would hand code execution on the bench to anyone who opens a PR.
  Schedule and `workflow_dispatch` only: both run code from the default branch
  or a ref a maintainer explicitly picks.
- Keep the runner dedicated to this repository (or in a runner group restricted
  to it), with `permissions: contents: read` in the workflow.
- The bench host needs no secrets: the job checks out public code, builds it,
  and talks to two radios. Don't give it any.

## Multi-hop field row

The multi-hop field criterion uses the same endpoint bench: add a third
stock-firmware radio on the same channel as a pure repeater (no USB connection:
powered, in range of both endpoints, with the endpoint radios' RF attenuated or
separated so they only reach each other through it). The test is unchanged:
routing is the mesh firmware's business, and Komms neither knows nor cares how
many hops a sealed frame took.

To call the row passed, do not infer multi-hop merely because the repeater was
powered:

1. With the repeater off, verify the endpoint radios cannot exchange ordinary
   Meshtastic traffic or the Komms HIL flight across the attenuated/separated
   setup.
2. Record the endpoint and repeater board models, stock firmware releases,
   region and modem preset without retaining hardware serial identifiers.
3. Power the repeater without attaching it to the Komms host. Retain
   secret-free Meshtastic routing/neighbor evidence that the repeater
   forwarded the test flight.
4. Run the HIL cases serially and retain exact frame/airtime output.
5. Turn the repeater off again and repeat the negative control.

A shielded box, legal RF attenuator, or sufficient physical separation is
preferable to reducing a region/power setting below legal or
firmware-supported operation. The field form records the topology, negative
controls, timings, failures, and retest disposition.

## Internet-bridge field row

The ignored bridge HIL case proves that real serial/RF traffic crosses the
production bridge and durable mailbox path to a local QUIC endpoint in both
directions. The stronger Internet-bridge row additionally requires a
separately reachable physical endpoint/network:

1. Keep the mesh endpoint radio-only: loopback listener, mDNS disabled, no
   bootstrap, direct, LAN, or alternate mailbox route.
2. Attach the second radio to the bridge. Give the bridge one publicly
   recorded test listen route and a dedicated mailbox-v2 store; retain no user
   identity or contact on the bridge.
3. Put the Internet endpoint on a separately administered network. Configure
   only the bridge mailbox route for the mesh contact.
4. Exchange a PQXDH first message and receipt mesh-to-Internet, then a
   ratcheted reply and receipt Internet-to-mesh.
5. Restart the bridge after deposit, during a lease, and before exact
   acknowledgement. Then blackhole each side. Verify deduplication, durable
   custody, unrelated rows, duty-cycle accounting, and delivery states.
6. Retain aggregate mailbox and `KOMMS_HIL_RESULT` evidence, source and image
   digests, network conditions, and timings through the field form.

The bridge sees route metadata, timing, volume, opaque tokens, and ciphertext.
It is not described as unable to observe or interfere. A same-host local-QUIC
run remains `observed`; only the separately reachable physical run may pass
the Internet-bridge row.
