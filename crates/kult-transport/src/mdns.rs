//! mDNS LAN auto-discovery (docs/05-transports.md §3), speaking the libp2p
//! mDNS discovery profile — PTR queries for `_p2p._udp.local` answered with
//! a TXT record of `dnsaddr=<multiaddr>/p2p/<peer-id>` strings — so kult
//! nodes also see (and are seen by) other libp2p implementations on the
//! same network.
//!
//! This is a deliberately small in-tree implementation (ADR-0008): the
//! upstream `libp2p-mdns` behaviour still depends on `hickory-proto 0.25`,
//! which carries open RUSTSEC advisories (2026-0118/0119), and this
//! workspace ships zero ignored vulnerabilities. The DNS subset the
//! discovery profile needs is tiny — one PTR question, one PTR answer, one
//! TXT record — and the parser below is strict and bounded by construction:
//! record counts are capped, name decompression caps pointer jumps and
//! output length, oversized or truncated data is dropped, never guessed at.
//!
//! Discovery is push *and* pull, so two nodes find each other within a
//! round-trip of the later start: every node multicasts a query when it
//! starts, multicasts an unsolicited announcement whenever its listen
//! addresses change (and again on every query tick, keeping records fresh
//! within their TTL), and answers queries it hears. Parsed announcements
//! flow to the swarm task, which feeds them into the Kademlia routing
//! table — that is what makes LAN-only operation (DHT publish/lookup and
//! delivery with **zero** configured bootstrap peers) work.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

/// The well-known mDNS multicast group and port (RFC 6762).
const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;

/// The libp2p discovery service name, as dotted lowercase labels.
const SERVICE_NAME: &str = "_p2p._udp.local";
const SERVICE_LABELS: [&str; 3] = ["_p2p", "_udp", "local"];

const TYPE_PTR: u16 = 12;
const TYPE_TXT: u16 = 16;
const TYPE_ANY: u16 = 255;
const CLASS_IN: u16 = 1;

/// Advertised record lifetime. Peers drop us this long after our last
/// announcement; announcements repeat every [`QUERY_INTERVAL`], well inside.
const RECORD_TTL: Duration = Duration::from_secs(6 * 60);

/// How often to re-query and re-announce. Discovery does not wait on this —
/// startup sends immediately — it only bounds staleness.
const QUERY_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// A hostile answer cannot pin itself in our LAN table indefinitely: claimed
/// TTLs are clamped here on parse.
const MAX_TTL: Duration = Duration::from_secs(30 * 60);

/// Minimum spacing between multicast responses (RFC 6762 §6 requires ≥ 1 s
/// per record) — also the cap on response traffic a query-flooding LAN peer
/// can draw out of us.
const RESPONSE_SPACING: Duration = Duration::from_secs(1);

/// Receive buffer; larger packets are truncated and then fail parsing.
const MAX_PACKET: usize = 4096;

/// Cap on questions + records walked per packet, and on addresses accepted
/// per packet — bounds on work a single multicast datagram can cause.
const MAX_ENTRIES: usize = 32;
const MAX_ADDRS: usize = 64;

/// Cap on an encoded response (fits any Ethernet MTU with headroom);
/// addresses that would not fit are dropped, earlier ones still go out.
const MAX_RESPONSE: usize = 1400;

/// One peer's presence extracted from an mDNS response.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DiscoveredPeer {
    /// Its transport pseudonym (never a kult identity — contract rule 2).
    pub peer: PeerId,
    /// Dialable addresses, trailing `/p2p/…` stripped.
    pub addrs: Vec<Multiaddr>,
    /// How long the peer asked to be remembered (clamped to [`MAX_TTL`]).
    pub ttl: Duration,
}

/// Everything actionable in one received datagram.
#[derive(Debug, Default)]
pub(crate) struct Packet {
    /// Someone asked for `_p2p._udp.local` — we should answer.
    pub service_query: bool,
    /// Peers announced by the sender (never includes ourselves).
    pub peers: Vec<DiscoveredPeer>,
}

/// Open the shared mDNS socket: port 5353 with address reuse (mDNS is a
/// shared medium — other responders on the host are normal), joined to the
/// multicast group on the default interface, with loopback enabled so
/// same-host peers see each other.
pub(crate) fn mdns_socket() -> io::Result<std::net::UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT).into())?;
    socket.join_multicast_v4(&MDNS_GROUP, &Ipv4Addr::UNSPECIFIED)?;
    socket.set_multicast_loop_v4(true)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

/// The discovery task. Lives next to the swarm task: `addrs` mirrors the
/// swarm's listen addresses (announce on change), discovered peers flow out
/// through `found`. Exits when either side of those channels is dropped —
/// i.e. when the transport shuts down.
pub(crate) async fn run_mdns(
    socket: UdpSocket,
    local: PeerId,
    mut addrs: watch::Receiver<Vec<Multiaddr>>,
    found: mpsc::UnboundedSender<DiscoveredPeer>,
) {
    let dest = SocketAddr::from((MDNS_GROUP, MDNS_PORT));
    let query = encode_query();
    let mut timer = tokio::time::interval(QUERY_INTERVAL);
    let mut last_response: Option<Instant> = None;
    let mut buf = [0u8; MAX_PACKET];
    loop {
        tokio::select! {
            // First tick is immediate: query the LAN as soon as we start.
            _ = timer.tick() => {
                let _ = socket.send_to(&query, dest).await;
                let ours = lan_addrs(&addrs.borrow());
                if let Some(packet) = encode_response(&local, &ours) {
                    let _ = socket.send_to(&packet, dest).await;
                }
            }
            changed = addrs.changed() => {
                // Sender dropped: the swarm task is gone, so are we.
                if changed.is_err() {
                    return;
                }
                // Unsolicited announcement (RFC 6762 §8.3): this is how the
                // *earlier*-started node learns about the later one.
                let ours = lan_addrs(&addrs.borrow_and_update().clone());
                if let Some(packet) = encode_response(&local, &ours) {
                    let _ = socket.send_to(&packet, dest).await;
                }
            }
            received = socket.recv_from(&mut buf) => {
                let Ok((len, _)) = received else { continue };
                let Some(packet) = parse_packet(&buf[..len], &local) else { continue };
                for peer in packet.peers {
                    if found.send(peer).is_err() {
                        return;
                    }
                }
                let due = last_response
                    .is_none_or(|at| at.elapsed() >= RESPONSE_SPACING);
                if packet.service_query && due {
                    let ours = lan_addrs(&addrs.borrow());
                    if let Some(packet) = encode_response(&local, &ours) {
                        last_response = Some(Instant::now());
                        let _ = socket.send_to(&packet, dest).await;
                    }
                }
            }
        }
    }
}

/// Addresses worth advertising on a LAN: everything the swarm listens on
/// except relay circuits — meaningless off the internet, and they embed
/// another peer's id.
fn lan_addrs(addrs: &[Multiaddr]) -> Vec<Multiaddr> {
    addrs
        .iter()
        .filter(|a| a.iter().all(|p| !matches!(p, Protocol::P2pCircuit)))
        .cloned()
        .collect()
}

/// The one query the profile needs: PTR for the service name.
fn encode_query() -> Vec<u8> {
    let mut out = vec![
        0, 0, // id 0 (mDNS)
        0, 0, // flags: standard query
        0, 1, // one question
        0, 0, 0, 0, 0, 0, // no records
    ];
    push_service_name(&mut out);
    out.extend_from_slice(&TYPE_PTR.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out
}

/// The one response/announcement the profile needs: a PTR answer mapping
/// the service name to our peer label, plus a TXT additional carrying one
/// `dnsaddr=<addr>/p2p/<id>` string per address. `None` when nothing fits
/// (no addresses yet, or every one oversized).
fn encode_response(local: &PeerId, addrs: &[Multiaddr]) -> Option<Vec<u8>> {
    let ttl = (RECORD_TTL.as_secs() as u32).to_be_bytes();
    // <peer-label>._p2p._udp.local — used as PTR target and TXT owner.
    let mut peer_dns_name = Vec::new();
    let label = peer_label(local);
    peer_dns_name.push(label.len() as u8);
    peer_dns_name.extend_from_slice(label.as_bytes());
    push_service_name(&mut peer_dns_name);

    let mut out = vec![
        0, 0, // id 0
        0x84, 0, // flags: response, authoritative
        0, 0, // no questions
        0, 1, // one answer
        0, 0, // no authority records
        0, 1, // one additional
    ];
    // Answer: _p2p._udp.local PTR <peer-label>._p2p._udp.local
    push_service_name(&mut out);
    out.extend_from_slice(&TYPE_PTR.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&ttl);
    out.extend_from_slice(&(peer_dns_name.len() as u16).to_be_bytes());
    out.extend_from_slice(&peer_dns_name);
    // Additional: <peer-label>._p2p._udp.local TXT dnsaddr=…
    out.extend_from_slice(&peer_dns_name);
    out.extend_from_slice(&TYPE_TXT.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&ttl);
    let mut txt = Vec::new();
    for addr in addrs {
        let s = format!("dnsaddr={addr}/p2p/{local}");
        // TXT strings carry a one-byte length; longer addresses are dropped,
        // as are ones that would push the packet past a safe datagram size.
        if s.len() > u8::MAX as usize || out.len() + txt.len() + 3 + s.len() > MAX_RESPONSE {
            continue;
        }
        txt.push(s.len() as u8);
        txt.extend_from_slice(s.as_bytes());
    }
    if txt.is_empty() {
        return None;
    }
    out.extend_from_slice(&(txt.len() as u16).to_be_bytes());
    out.extend_from_slice(&txt);
    Some(out)
}

/// The DNS label naming this peer's records: lowercase hex of the peer id's
/// leading bytes, trimmed to the 63-char label limit. The label only links
/// the PTR answer to the TXT record — everyone (including us) reads peer
/// ids from the `dnsaddr` strings, never from the label.
fn peer_label(peer: &PeerId) -> String {
    peer.to_bytes()
        .iter()
        .take(31)
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Append the service name in wire form (no compression — spec-legal and
/// simple).
fn push_service_name(out: &mut Vec<u8>) {
    for label in SERVICE_LABELS {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// Parse one datagram. `None` means "nothing usable" — malformed, oversized
/// counts, or truncated data; there is no partial trust in a broken packet.
/// `local` filters our own multicast-looped announcements out of `peers`.
pub(crate) fn parse_packet(buf: &[u8], local: &PeerId) -> Option<Packet> {
    if buf.len() < 12 {
        return None;
    }
    let is_response = buf[2] & 0x80 != 0;
    let questions = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let records = u16::from_be_bytes([buf[6], buf[7]]) as usize
        + u16::from_be_bytes([buf[8], buf[9]]) as usize
        + u16::from_be_bytes([buf[10], buf[11]]) as usize;
    if questions + records > MAX_ENTRIES {
        return None;
    }

    let mut packet = Packet::default();
    let mut pos = 12;
    for _ in 0..questions {
        let name = read_name(buf, &mut pos)?;
        let qtype = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]);
        pos = pos.checked_add(4)?;
        if pos > buf.len() {
            return None;
        }
        if !is_response && name == SERVICE_NAME && (qtype == TYPE_PTR || qtype == TYPE_ANY) {
            packet.service_query = true;
        }
    }

    let mut accepted = 0;
    for _ in 0..records {
        // The owner name only links records together; peers come from the
        // dnsaddr strings, so it is read (bounds-checked) and dropped.
        read_name(buf, &mut pos)?;
        if buf.len() < pos + 10 {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        let rdata = buf.get(pos..pos + rdlen)?;
        pos += rdlen;
        // TTL 0 is a goodbye: nothing to add, and expiry handles the rest.
        if rtype != TYPE_TXT || ttl == 0 {
            continue;
        }
        let ttl = MAX_TTL.min(Duration::from_secs(u64::from(ttl)));
        for string in txt_strings(rdata) {
            let Some(addr) = string.strip_prefix(b"dnsaddr=") else {
                continue;
            };
            let Ok(addr) = std::str::from_utf8(addr) else {
                continue;
            };
            let Ok(addr) = addr.parse::<Multiaddr>() else {
                continue;
            };
            let Some((peer, addr)) = split_trailing_peer(addr) else {
                continue;
            };
            if peer == *local || accepted >= MAX_ADDRS {
                continue;
            }
            accepted += 1;
            match packet.peers.iter_mut().find(|p| p.peer == peer) {
                Some(entry) => {
                    if !entry.addrs.contains(&addr) {
                        entry.addrs.push(addr);
                    }
                    entry.ttl = entry.ttl.max(ttl);
                }
                None => packet.peers.push(DiscoveredPeer {
                    peer,
                    addrs: vec![addr],
                    ttl,
                }),
            }
        }
    }
    Some(packet)
}

/// Decode a (possibly compressed) DNS name at `*pos`, advancing `*pos` past
/// it in the record stream. Strict and bounded: pointer chains cap at 8
/// jumps, output caps at the RFC's 255 bytes, truncation is an error.
/// Canonicalized to lowercase (DNS names compare case-insensitively).
fn read_name(buf: &[u8], pos: &mut usize) -> Option<String> {
    const MAX_JUMPS: usize = 8;
    let mut out = String::new();
    let mut cur = *pos;
    let mut jumps = 0;
    // Where the name ends in the record stream: after the first pointer, or
    // after the terminator if the name never jumps.
    let mut end = None;
    loop {
        let len = *buf.get(cur)? as usize;
        match len {
            0 => {
                *pos = end.unwrap_or(cur + 1);
                return Some(out);
            }
            // Compression pointer (0b11……): jump caps make loops finite,
            // and the backwards-only rule rejects the pathological ones
            // outright.
            l if l & 0xC0 == 0xC0 => {
                let target = ((l & 0x3F) << 8) | *buf.get(cur + 1)? as usize;
                if end.is_none() {
                    end = Some(cur + 2);
                }
                jumps += 1;
                if jumps > MAX_JUMPS || target >= cur {
                    return None;
                }
                cur = target;
            }
            // Ordinary label (0b00……, so ≤ 63 bytes by construction).
            l if l & 0xC0 == 0 => {
                let label = buf.get(cur + 1..cur + 1 + l)?;
                if out.len() + l + 1 > 255 {
                    return None;
                }
                if !out.is_empty() {
                    out.push('.');
                }
                out.extend(label.iter().map(|b| b.to_ascii_lowercase() as char));
                cur += 1 + l;
            }
            // 0b01/0b10 label types: not a thing in mDNS.
            _ => return None,
        }
    }
}

/// Split TXT RDATA into its length-prefixed strings. A truncated final
/// string drops silently — earlier strings are still well-formed.
fn txt_strings(rdata: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut pos = 0;
    std::iter::from_fn(move || {
        let len = *rdata.get(pos)? as usize;
        let string = rdata.get(pos + 1..pos + 1 + len)?;
        pos += 1 + len;
        Some(string)
    })
}

/// Split `…/p2p/<id>` into the dialable address and the peer id. Addresses
/// without a trailing peer id are useless for discovery and dropped.
fn split_trailing_peer(mut addr: Multiaddr) -> Option<(PeerId, Multiaddr)> {
    match addr.pop() {
        Some(Protocol::P2p(peer)) if !addr.is_empty() => Some((peer, addr)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerId {
        PeerId::random()
    }

    fn addr(port: u16) -> Multiaddr {
        format!("/ip4/192.168.1.9/udp/{port}/quic-v1")
            .parse()
            .unwrap()
    }

    #[test]
    fn query_round_trips() {
        let me = peer();
        let packet = parse_packet(&encode_query(), &me).unwrap();
        assert!(packet.service_query);
        assert!(packet.peers.is_empty());
    }

    #[test]
    fn response_round_trips() {
        let (me, them) = (peer(), peer());
        let advertised = vec![addr(4001), addr(4002)];
        let bytes = encode_response(&them, &advertised).unwrap();
        // Not a query for us to answer…
        let packet = parse_packet(&bytes, &me).unwrap();
        assert!(!packet.service_query);
        // …but exactly one discovered peer, addresses intact, TTL as sent.
        assert_eq!(packet.peers.len(), 1);
        assert_eq!(packet.peers[0].peer, them);
        assert_eq!(packet.peers[0].addrs, advertised);
        assert_eq!(packet.peers[0].ttl, RECORD_TTL);
    }

    #[test]
    fn own_announcements_are_filtered() {
        let me = peer();
        let bytes = encode_response(&me, &[addr(4001)]).unwrap();
        let packet = parse_packet(&bytes, &me).unwrap();
        assert!(packet.peers.is_empty());
    }

    #[test]
    fn empty_address_list_encodes_nothing() {
        assert!(encode_response(&peer(), &[]).is_none());
    }

    #[test]
    fn oversized_addresses_are_dropped_not_truncated() {
        // A multiaddr rendering longer than a TXT string can carry.
        let huge: Multiaddr = format!("/dns4/{}.example/tcp/1", "x".repeat(300))
            .parse()
            .unwrap();
        assert!(encode_response(&peer(), std::slice::from_ref(&huge)).is_none());
        // Mixed with a normal address, the normal one still goes out.
        let bytes = encode_response(&peer(), &[huge, addr(4001)]).unwrap();
        let packet = parse_packet(&bytes, &peer()).unwrap();
        assert_eq!(packet.peers[0].addrs, vec![addr(4001)]);
    }

    #[test]
    fn truncated_packets_are_rejected() {
        let bytes = encode_response(&peer(), &[addr(4001)]).unwrap();
        for cut in [0, 5, 11, 13, bytes.len() / 2, bytes.len() - 1] {
            assert!(parse_packet(&bytes[..cut], &peer()).is_none(), "cut={cut}");
        }
    }

    #[test]
    fn absurd_record_counts_are_rejected() {
        let mut bytes = encode_response(&peer(), &[addr(4001)]).unwrap();
        bytes[6] = 0xFF; // claim 65280+ answers
        assert!(parse_packet(&bytes, &peer()).is_none());
    }

    #[test]
    fn compression_pointer_loops_are_rejected() {
        // A question whose name is a pointer at offset 12 pointing forward
        // to itself — the classic decompression loop.
        let mut bytes = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        bytes.extend_from_slice(&[0xC0, 12]); // pointer → offset 12 (itself)
        bytes.extend_from_slice(&TYPE_PTR.to_be_bytes());
        bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
        assert!(parse_packet(&bytes, &peer()).is_none());
    }

    #[test]
    fn forward_pointers_are_rejected() {
        let mut bytes = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        bytes.extend_from_slice(&[0xC0, 20]); // pointer → past itself
        bytes.extend_from_slice(&TYPE_PTR.to_be_bytes());
        bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
        bytes.resize(64, 0);
        assert!(parse_packet(&bytes, &peer()).is_none());
    }

    #[test]
    fn backward_pointer_chains_still_terminate() {
        // A backwards pointer that re-enters the labels leading to itself:
        // "a" at 12, pointer at 14 → 12 → "a" → the same pointer, forever.
        // Each individual jump is backwards, so only the jump cap (and the
        // 255-byte name cap) end it.
        let mut bytes = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        bytes.extend_from_slice(&[1, b'a', 0xC0, 12]);
        bytes.extend_from_slice(&TYPE_PTR.to_be_bytes());
        bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
        assert!(parse_packet(&bytes, &peer()).is_none());
    }

    #[test]
    fn compressed_names_from_other_implementations_parse() {
        // Handcraft a response the way a compressing encoder would emit it:
        // question at 12, answer name is a pointer back to it.
        let them = peer();
        let dnsaddr = format!("dnsaddr={}/p2p/{them}", addr(4001));
        let mut bytes = vec![0, 0, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0];
        push_service_name(&mut bytes); // question name at offset 12
        bytes.extend_from_slice(&TYPE_PTR.to_be_bytes());
        bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
        bytes.extend_from_slice(&[0xC0, 12]); // answer owner → offset 12
        bytes.extend_from_slice(&TYPE_TXT.to_be_bytes());
        bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
        bytes.extend_from_slice(&120u32.to_be_bytes());
        bytes.extend_from_slice(&((dnsaddr.len() + 1) as u16).to_be_bytes());
        bytes.push(dnsaddr.len() as u8);
        bytes.extend_from_slice(dnsaddr.as_bytes());
        let packet = parse_packet(&bytes, &peer()).unwrap();
        assert_eq!(packet.peers[0].peer, them);
        assert_eq!(packet.peers[0].addrs, vec![addr(4001)]);
        assert_eq!(packet.peers[0].ttl, Duration::from_secs(120));
    }

    #[test]
    fn hostile_ttls_are_clamped_and_goodbyes_skipped() {
        let them = peer();
        let build = |ttl: u32| {
            let dnsaddr = format!("dnsaddr={}/p2p/{them}", addr(4001));
            let mut bytes = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
            push_service_name(&mut bytes);
            bytes.extend_from_slice(&TYPE_TXT.to_be_bytes());
            bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
            bytes.extend_from_slice(&ttl.to_be_bytes());
            bytes.extend_from_slice(&((dnsaddr.len() + 1) as u16).to_be_bytes());
            bytes.push(dnsaddr.len() as u8);
            bytes.extend_from_slice(dnsaddr.as_bytes());
            bytes
        };
        let me = peer();
        let forever = parse_packet(&build(u32::MAX), &me).unwrap();
        assert_eq!(forever.peers[0].ttl, MAX_TTL);
        let goodbye = parse_packet(&build(0), &me).unwrap();
        assert!(goodbye.peers.is_empty());
    }

    #[test]
    fn non_dnsaddr_and_malformed_strings_are_ignored() {
        let them = peer();
        let good = format!("dnsaddr={}/p2p/{them}", addr(4001));
        let strings: &[&[u8]] = &[
            b"printer=yes",                    // unrelated TXT data
            b"dnsaddr=not a multiaddr",        // unparseable
            b"dnsaddr=/ip4/10.0.0.1/tcp/4001", // no trailing /p2p/…
            b"dnsaddr=\xFF\xFE",               // not UTF-8
            good.as_bytes(),
        ];
        let mut txt = Vec::new();
        for s in strings {
            txt.push(s.len() as u8);
            txt.extend_from_slice(s);
        }
        let mut bytes = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        push_service_name(&mut bytes);
        bytes.extend_from_slice(&TYPE_TXT.to_be_bytes());
        bytes.extend_from_slice(&CLASS_IN.to_be_bytes());
        bytes.extend_from_slice(&120u32.to_be_bytes());
        bytes.extend_from_slice(&(txt.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&txt);
        let packet = parse_packet(&bytes, &peer()).unwrap();
        assert_eq!(packet.peers.len(), 1);
        assert_eq!(packet.peers[0].addrs, vec![addr(4001)]);
    }

    #[test]
    fn random_garbage_never_panics() {
        // Deterministic pseudo-random bytes: a cheap fuzz pass over the
        // whole parser (names, records, TXT walking).
        let mut state = 0x2545F4914F6CDD1Du64;
        for len in 0..512 {
            let bytes: Vec<u8> = (0..len)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state as u8
                })
                .collect();
            let _ = parse_packet(&bytes, &peer());
        }
    }
}
