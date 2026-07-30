# Operating modes and replaceable provider configuration

Komms has one protocol and three network-policy modes. Changing mode does not
change an account identity, safety number, message format, ratchet, group
trust, local history, pending work, or delivery meaning. It changes only which
optional routes may be used and what discovery data may be published.

This document describes the implemented Alpha contract. It is not evidence of
a deployed default provider, non-colluding Private ingress, distinct-NAT
qualification, or physical-device behavior.

## 1. One mode contract

| Mode | Optional rendezvous | Public Connect record | Core and user routes |
|---|---|---|---|
| **Standard** | Direct pinned TLS 1.3 after the metadata disclosure is confirmed | No direct route | Preserved |
| **Private** | Pinned TLS 1.3 through an explicit loopback Tor SOCKS5 proxy | No direct route | Preserved |
| **Sovereign** | Disabled | Direct route only after the separate warning acknowledgement | Preserved |

Core and user routes include capability-scoped DHT discovery, user-selected
mailboxes, QR/file exchange, direct hints, LAN, mesh, and sneakernet. Sovereign
mode disables directory-supplied defaults as well as rendezvous; it does not
delete user-selected routes. A mode change cannot mark a message sent or
delivered.

The status vocabulary is deliberately small:

- **Connected** means at least one current peer connection exists.
- **Fallback ready** means a configured mailbox, relay, LAN, file, or mesh path
  remains available for ordinary retry.
- **Waiting for a route** means no current connection or configured fallback is
  known. It is not a delivery failure.
- **Private** identifies the selected network policy. It does not claim
  anonymity, non-collusion, or protection from a global observer.

The same version-1 settings shape is pinned by
[`operating-mode-settings-v1.json`](../fixtures/operating-mode-settings-v1.json)
and consumed unchanged by desktop, Android, and iOS. Unknown mode names fail
closed.

## 2. Signed provider directory

A directory is optional. It can add disclosed bootstrap, relay, mailbox, and
rendezvous entries, but cannot replace identity or message authority. Manual
entries are applied first and remain when the directory is unavailable,
expired, conflicting, disabled, or replaced.

The version-1 JSON document contains:

- a positive, strictly increasing generation;
- a bounded validity interval;
- the digest of the complete accepted parent;
- the exact Ed25519 signing key and an optional future key plus activation
  generation;
- sorted, unique operator records with an administrative domain and bounded
  role entries; and
- an Ed25519 signature over the deterministic binary form of every preceding
  field.

The implementation accepts at most 256 KiB, eight configured offline roots, a
16-generation retained chain, 32 operators, and eight entries per operator
role. At most eight rendezvous providers are effective at once; manual entries
take precedence and directory defaults fill only remaining slots. One document
is valid for at most 90 days. An expired last-valid directory has a visible
30-day outage grace; after that, directory defaults are disabled. Parsing
rejects unknown JSON fields, non-canonical hexadecimal, unsorted or duplicate
records, invalid multiaddresses, non-HTTPS rendezvous, invalid TLS pins,
rollback, forked parents, and unauthorized key changes.

The cache is replaced atomically only after complete verification. An invalid
candidate cannot replace the last valid generation. A corrupt or
cryptographically conflicting retained cache is reported as **conflict** and
directory defaults fail closed; ordering never chooses a new authority.
Removing the configured directory path is an explicit opt-out: cached defaults
stop immediately while the cache remains available if the user later restores
the configuration.

Directory states exposed through the daemon, UniFFI, and shells are
`current`, `retained_last_valid`, `stale`, `conflict`, `unavailable`, and
`not_configured`.

Komms does not currently ship a production directory, production root key, or
qualified default operator. A directory signature authenticates configuration
provenance, not operator honesty, availability, independence, or safety.

## 3. Rendezvous transport boundary

Every rendezvous entry binds a canonical HTTPS origin to the SHA-256 digest of
its exact leaf certificate. Standard uses a direct TLS 1.3 connection. Private
requires a numeric, non-zero loopback Tor SOCKS5 endpoint; DNS resolution is
performed through Tor and stream-isolation credentials separate requests.
There is no direct fallback if the proxy or provider fails.

Requests use the fixed binary ADR-0018 register and lookup bodies over one
bounded HTTP/1.1 exchange. Redirects, cookies, compression, proxy
authentication, URL capabilities, unpinned certificates, older TLS versions,
variable response bodies, and response overrun are rejected.

The implemented Tor path is a local client boundary. It does not by itself earn
a claim that a particular Tor exit, provider, OHTTP relay, or administrative
domain is independent or non-colluding.

## 4. Daemon configuration

The relevant `kultd` options are:

```text
--mode standard|private|sovereign
--confirm-standard-provider-disclosure
--sovereign-publish-direct-routes
--provider-directory FILE
--provider-directory-root 64_LOWERCASE_HEX
--rendezvous ORIGIN,LEAF_SHA256,standard|private|both
--tor-proxy 127.0.0.1:9050
```

`--provider-directory-root` and `--rendezvous` are repeatable. A configured
directory without a trusted root is refused. Standard directory defaults are
refused until the disclosure flag is present. Private rendezvous is refused
without a valid loopback Tor endpoint. Manual rendezvous entries remain
subject to the selected mode.

For a pure-core node, omit the directory and rendezvous options. Configure only
the user-selected bootstrap, mailbox, relay, LAN, file, or mesh routes that the
deployment needs. Sovereign is the clearest policy for that profile.

## 5. Repeatable local journeys and evidence boundary

Run:

```sh
scripts/test-operating-mode-journeys.sh
```

The gate covers a signed Standard configuration, manual alternate bootstrap,
configured-default blackhole with bounded last-valid retention, authenticated
operator replacement, explicit directory opt-out, pure-core/Sovereign
operation, Connect-code first contact, provisional consent, offline durable
mailbox delivery, authenticated route repair, rendezvous source merging,
recovery rekeying, restart persistence, and the shared desktop/Android/iOS
settings contract.

These are hermetic host and localhost journeys. They do not close P0-04 or
P0-09. The following still require named environments and retained
revision-bound results:

- two clean supported devices behind distinct ordinary NATs;
- default and alternate operators reached over real networks;
- a deployed default blackhole and independently operated replacement;
- Tor or separated OHTTP ingress with the claimed administrative domains;
- Wi-Fi/cellular handoff and mobile background lifecycle;
- physical Android and iOS devices; and
- complete optional-service failure while qualified direct, mailbox, LAN,
  mesh, and sneakernet routes remain usable.

Native wake is a separate ADR-0019 implementation and qualification boundary.
