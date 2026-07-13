# ADR-0008: In-tree mDNS responder instead of libp2p-mdns

- **Status**: Accepted
- **Date**: 2026-07-12

## Context

M3's last acceptance criterion is LAN-only delivery via mDNS auto-discovery
([05: Transports §3](../05-transports.md), [08: Roadmap](../08-roadmap.md)). The
obvious implementation is the `mdns` feature of rust-libp2p (ADR-0004), but
`libp2p-mdns` (0.48.0 at the time of writing) pins `hickory-proto ^0.25`, and the
0.25 line carries two unpatched RUSTSEC advisories (RUSTSEC-2026-0118/0119, DoS in
DNSSEC validation paths; fixed only in the 0.26 rewrite that splits the crate). This
workspace ships **zero ignored vulnerability advisories** (cargo-deny fails CI
otherwise) and the feature was deferred on exactly that ground.

Waiting is open-ended (the upstream bump is tied to a major hickory restructuring),
and ignoring the advisories with a "probably unreachable from mDNS" justification
would put an asterisk on the project's cleanest supply-chain claim.

## Decision

Implement the libp2p mDNS discovery profile in-tree (`kult-transport/src/mdns.rs`):
one PTR question for `_p2p._udp.local`, one PTR answer, one TXT record of
`dnsaddr=<multiaddr>/p2p/<peer-id>` strings. The parser is strict and bounded by
construction (capped record counts, capped name-decompression jumps, capped output
length, malformed input dropped whole) and carries unit tests for the classic DNS
parser attacks (pointer loops, forward pointers, truncation, hostile TTLs) plus a
deterministic fuzz pass. Discovered peers are fed into the Kademlia routing table,
which is what makes LAN-only DHT operation (prekey publish/lookup with zero bootstrap
peers) work. Same wire profile as everyone else, so interop with other libp2p nodes
is preserved.

The dependency note in `kult-transport/Cargo.toml` keeps the pointer: if a future
`libp2p-mdns` drops the flagged dependency line, switching back is a contained,
behaviour-preserving swap. This ADR does not marry the project to the in-tree
responder, it refuses the vulnerable dependency.

## Alternatives considered

- **Wait for upstream.** No date attached; M3 stays open on a criterion users feel
  ("internet is down but the building network works"). LAN delivery via explicit
  multiaddrs worked, but "type your peer's socket address" is not auto-discovery.
- **Enable the feature and ignore the advisories with reasons.** The advisories sit in
  DNSSEC validation code mDNS likely never reaches, so an ignore would probably be
  *safe*, but "zero ignored vulnerabilities" is a stronger, simpler claim than "the
  ignored ones are unreachable, trust our reachability analysis", and reachability can
  silently change on any upstream refactor.
- **A third-party mDNS crate (`mdns-sd`, `simple-mdns`, …).** Swaps an audited-by-many
  dependency for a smaller, less-scrutinized one *and* still requires adapter code to
  speak the libp2p discovery profile; the profile subset is small enough that the
  adapter would dwarf the protocol code.

## Consequences

- ~600 lines of DNS wire code become ours to maintain: deliberately the smallest
  subset that speaks the profile (no compression on encode, IPv4 only to start,
  multicast responses only), hardened and fuzzed in-tree like `kult-protocol`'s codecs.
- The parser handles hostile LAN input by policy, not luck: every claim a packet makes
  (counts, lengths, TTLs, pointers) is bounded before use, and announcements only ever
  carry what an internet listener already reveals: the transport pseudonym and listen
  addresses, never the kult identity (contract rule 2).
- Group membership joins on the default multicast interface; exotic multi-homed hosts
  may need OS routing configured. Acceptable for M3; revisit alongside the M4/M5
  platform work if it bites.
- cargo-deny stays green with an empty vulnerability ignore list, which is the point.
