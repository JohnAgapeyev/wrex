//! NDP next-hop resolution for the raw v6 driver (tranche 10b): the
//! T7b on-link/`lo` contract closes with kernel route lookup plus a
//! small solicited-neighbor (RFC 4861 §7.2) cache.
//!
//! Hand-rolled wire bytes, not the `wrex-proto-icmpv6` codec — `wrex-io`
//! keeps no codec dependencies (the io layer stays independent of the
//! protocol registry), so the NS/NA shapes live here next to their only
//! consumer.
//!
//! ## Resolution contract
//!
//! - `/proc/net/ipv6_route` is read once at driver open (routes may
//!   drift later; a rescan is a deferral) and looked up by
//!   longest-prefix match per send.
//! - A **local** route (`RTF_LOCAL`), a multicast destination, or no
//!   route at all keeps the T7b behavior: inject with the interface
//!   MAC. `lo` never resolves NDP (its `::1` is a local route).
//! - An **on-link** route resolves the destination itself; a
//!   **gateway** route resolves the gateway. Resolution sends one
//!   multicast NS (solicited-node, SLLA carried) and waits a bounded
//!   `RESOLVE_TIMEOUT` for a matching NA; on silence it falls back to
//!   the interface MAC (never fatal — the probe still goes out).
//! - Resolution *does* consume unrelated frames that arrive during its
//!   bounded wait (best-effort: scans retransmit; the `lo`/local path
//!   that CI exercises never resolves).

use std::collections::HashMap;
use std::io;
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

/// One `/proc/net/ipv6_route` line for the egress interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Route {
    /// Network destination (already masked).
    pub dst: Ipv6Addr,
    /// Prefix length (0..=128).
    pub prefix: u32,
    /// Next-hop gateway (`None` = on-link / directly reachable).
    pub gateway: Option<Ipv6Addr>,
    /// `RTF_LOCAL` (a local address, not a forwardable route).
    pub local: bool,
}

/// `RTF_UP`-alike bit the kernel always sets on usable rows (the
/// least flag bit).
const RTF_UP: u32 = 0x1;
/// A local-address route (`::1/128` etc.) — never NDP-resolved.
const RTF_LOCAL: u32 = 0x8000_0000;

/// Parse the routes of one interface out of a `/proc/net/ipv6_route`
/// dump. Rows: `dst dstlen src srclen nexthop metric ref use flags
/// name` — all hex except the name. Unparsable rows are skipped
/// (never fatal).
pub(crate) fn parse_routes(dump: &str, iface: &str) -> Vec<Route> {
    let mut out = Vec::new();
    for line in dump.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 10 || f[9] != iface {
            continue;
        }
        let Some(dst) = parse_hex_ipv6(f[0]) else {
            continue;
        };
        let Ok(prefix) = u32::from_str_radix(f[1], 16) else {
            continue;
        };
        let Ok(flags) = u32::from_str_radix(f[8], 16) else {
            continue;
        };
        if flags & RTF_UP == 0 {
            continue; // dead route
        }
        let gateway = if f[4] == "00000000000000000000000000000000" {
            None
        } else {
            parse_hex_ipv6(f[4])
        };
        let prefix = prefix.min(128);
        out.push(Route {
            dst: mask_addr(dst, prefix),
            prefix,
            gateway,
            local: flags & RTF_LOCAL != 0,
        });
    }
    out
}

/// Longest-prefix match (the kernel's own route-selection order among
/// equal metrics; ties keep the first row — `/proc` order).
pub(crate) fn lookup(routes: &[Route], dst: Ipv6Addr) -> Option<&Route> {
    routes
        .iter()
        .filter(|r| mask_addr(dst, r.prefix) == r.dst)
        .max_by_key(|r| r.prefix)
}

/// Mask an address to its prefix length.
fn mask_addr(a: Ipv6Addr, prefix: u32) -> Ipv6Addr {
    if prefix == 0 {
        return Ipv6Addr::UNSPECIFIED;
    }
    if prefix > 128 {
        return a;
    }
    let mut oct = a.octets();
    let mut left = prefix;
    for b in oct.iter_mut() {
        match left {
            0 => *b = 0,
            8.. => {}
            _ => *b &= !(0xffu8 >> left),
        }
        left = left.saturating_sub(8);
    }
    Ipv6Addr::from(oct)
}

/// Parse 32 hex chars as a network-order v6 address.
fn parse_hex_ipv6(raw: &str) -> Option<Ipv6Addr> {
    let mut oct = [0u8; 16];
    let bytes = raw.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    for (i, o) in oct.iter_mut().enumerate() {
        let hi = (bytes[i * 2] as char).to_digit(16)?;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16)?;
        *o = (hi * 16 + lo) as u8;
    }
    Some(Ipv6Addr::from(oct))
}

/// Is this a multicast destination (`ff00::/8`)?
fn is_multicast(a: Ipv6Addr) -> bool {
    a.octets()[0] == 0xff
}

/// Solicited-node multicast address (RFC 4861 §4.3): `ff02::1:ffXX:XXXX`
/// from the low 24 bits of `target`.
pub fn solicited_node(target: Ipv6Addr) -> Ipv6Addr {
    let t = target.octets();
    let mut a = [0u8; 16];
    a[0] = 0xff;
    a[1] = 0x02;
    a[11] = 0x01;
    a[12] = 0xff;
    a[13] = t[13];
    a[14] = t[14];
    a[15] = t[15];
    Ipv6Addr::from(a)
}

/// Ethernet multicast MAC for a v6 multicast address (RFC 2464:
/// `33:33:` + the address's low 32 bits).
pub fn multicast_mac(a: Ipv6Addr) -> [u8; 6] {
    let o = a.octets();
    [0x33, 0x33, o[12], o[13], o[14], o[15]]
}

/// One's-complement checksum over the RFC 8200 §8.1 pseudo-header plus
/// the message (an independent fold — no codec dependency).
pub fn icmp6_checksum(src: Ipv6Addr, dst: Ipv6Addr, msg: &[u8]) -> u16 {
    let mut acc: u32 = 0;
    let add = |acc: &mut u32, bytes: &[u8]| {
        for (i, b) in bytes.iter().enumerate() {
            if i % 2 == 0 {
                *acc += (*b as u32) << 8;
            } else {
                *acc += *b as u32;
            }
        }
        if bytes.len() % 2 == 1 {
            *acc += 0x100; // trailing pad byte (RFC 1071)
        }
    };
    add(&mut acc, &src.octets());
    add(&mut acc, &dst.octets());
    // Upper-layer length (32-bit) + zeros + next header 58.
    add(&mut acc, &(msg.len() as u32).to_be_bytes());
    add(&mut acc, &[0, 58]);
    add(&mut acc, msg);
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// ICMPv6 NS type (RFC 4861).
const T_NS: u8 = 135;
/// ICMPv6 NA type (RFC 4861).
const T_NA: u8 = 136;
/// SLLA NDP option type (RFC 4861 §4.6.1).
const OPT_SLLA: u8 = 1;

/// Build one full Ethernet frame: NS for `target` (SLLA = `slla`)
/// from `src` to `target`'s solicited-node multicast.
pub fn build_ns_frame(
    iface_mac: [u8; 6],
    src: Ipv6Addr,
    target: Ipv6Addr,
    slla: [u8; 6],
) -> Vec<u8> {
    let sn = solicited_node(target);
    let dst_mac = multicast_mac(sn);
    // ICMPv6 body: type, code, ck, 4 reserved, 16 target, 8 SLLA option.
    let mut icmp = Vec::with_capacity(8 + 16 + 8);
    icmp.extend_from_slice(&[T_NS, 0, 0, 0]);
    icmp.extend_from_slice(&[0u8; 4]); // reserved
    icmp.extend_from_slice(&target.octets());
    icmp.extend_from_slice(&[OPT_SLLA, 1]); // type 1, one 8-byte unit
    icmp.extend_from_slice(&slla);
    // No pad: the SLLA option is exactly len×8 bytes (RFC 4861
    // §4.6.1) — 2 + 6. The tranche-17b codec/driver byte-identity
    // cross-check caught a 2-byte pad here that made the "option" 10
    // bytes, past its own declared length (the T10b unit goldens
    // self-confirmed the shape — the inversion-rule blind spot).
    let ck = icmp6_checksum(src, sn, &icmp);
    icmp[2] = ck.to_be_bytes()[0];
    icmp[3] = ck.to_be_bytes()[1];

    let mut frame = Vec::with_capacity(14 + 40 + icmp.len());
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&iface_mac);
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    // IPv6 header: version 6 (the 17b byte-identity cross-check caught
    // an all-zero flow word here — version 0, an invalid header), flow
    // 0, payload_len, next 58, hop 255 (NDP mandates 255 so receivers
    // never forward it).
    frame.extend_from_slice(&[0x60, 0, 0, 0]);
    frame.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
    frame.extend_from_slice(&[58, 255]);
    frame.extend_from_slice(&src.octets());
    frame.extend_from_slice(&sn.octets());
    frame.extend_from_slice(&icmp);
    frame
}

/// Parse an NA out of a full Ethernet frame: returns
/// `(na_target, sender_mac)` when the frame is an NA (type 136) over
/// IPv6 (ethertype 0x86dd). Best-effort: no checksum verify (the
/// resolution cache is advisory — a wrong entry costs one probe).
pub fn parse_na(frame: &[u8]) -> Option<(Ipv6Addr, [u8; 6])> {
    // Eth(14) + IPv6(40) + NA body(24): type/code/ck, flags, target.
    if frame.len() < 14 + 40 + 24 {
        return None;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != 0x86dd {
        return None;
    }
    if frame[14 + 6] != 58 {
        return None; // ipv6 next header is not ICMPv6
    }
    // eth.src bytes 6..12: the NA sender's own MAC.
    let sender_mac = [frame[6], frame[7], frame[8], frame[9], frame[10], frame[11]];
    let icmp = &frame[54..];
    if icmp[0] != T_NA {
        return None;
    }
    let target_oct: [u8; 16] = icmp[8..24].try_into().expect("8..24 is 16 bytes");
    let target = Ipv6Addr::from(target_oct);
    Some((target, sender_mac))
}

/// Bounded NS/NA resolution wait (one attempt; best-effort).
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(1);

/// Neighbor MAC cache: `target → [u8; 6]`, filled by the NS/NA
/// exchange, consulted before every send.
#[derive(Default)]
pub(crate) struct NdpCache {
    map: HashMap<Ipv6Addr, [u8; 6]>,
}

impl NdpCache {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn get(&self, target: &Ipv6Addr) -> Option<[u8; 6]> {
        self.map.get(target).copied()
    }

    pub(crate) fn put(&mut self, target: Ipv6Addr, mac: [u8; 6]) {
        self.map.insert(target, mac);
    }

    /// The Ethernet next-hop MAC for a v6 datagram destination, or
    /// `None` to keep the interface-MAC fallback (multicast/local/no
    /// route/failed resolution).
    ///
    /// `send_frame` injects raw frames on the driver's socket;
    /// `recv_frame` polls it (`Some((bytes, pkttype))` — outgoing
    /// copies included: the kernel's own NA reply comes back as
    /// `PACKET_OUTGOING` on the egress iface).
    pub(crate) fn next_hop_mac(
        &mut self,
        routes: &[Route],
        dst: Ipv6Addr,
        iface_mac: [u8; 6],
        source_ip: Ipv6Addr,
        send_frame: &mut dyn FnMut(&[u8]) -> io::Result<()>,
        recv_frame: &mut dyn FnMut(Instant) -> io::Result<Option<(Vec<u8>, u8)>>,
    ) -> io::Result<Option<[u8; 6]>> {
        if is_multicast(dst) || dst.is_unspecified() {
            // Multicast maps directly (RFC 2464); no cache involved.
            return Ok(Some(multicast_mac(dst)));
        }
        let Some(route) = lookup(routes, dst) else {
            return Ok(None); // no route: iface-MAC fallback
        };
        if route.local {
            return Ok(None); // local address (lo): iface-MAC fallback
        }
        // On-link resolves the destination; a gateway route resolves
        // the gateway (the destination's MAC is the gateway's).
        let target = route.gateway.unwrap_or(dst);
        if let Some(mac) = self.get(&target) {
            return Ok(Some(mac));
        }
        // Resolve: one NS, bounded wait. The NS source may be
        // unspecified (DAD form) — the kernel still answers for its
        // own addresses, which covers the lo/bridge cases; real
        // off-link peers answer a proper source.
        let ns = build_ns_frame(iface_mac, source_ip, target, iface_mac);
        let deadline = Instant::now() + RESOLVE_TIMEOUT;
        send_frame(&ns)?;
        while let Some((frame, _pkttype)) = recv_frame(deadline)? {
            if let Some((na_target, mac)) = parse_na(&frame)
                && na_target == target
            {
                self.put(target, mac);
                return Ok(Some(mac));
            }
            // Not our NA: keep polling until the deadline.
        }
        Ok(None) // resolution failed: iface-MAC fallback, never fatal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    const DUMP: &str = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000006eb311fffe1c9579 00000064 00000021 00000000 00200003   enp5s0
fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000400 00000002 00000000 00000001   enp5s0
00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 0000001f 00000000 80200001       lo
2001056977ffb8000000000000002000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000064 00000005 00000000 00000001   enp5s0
garbage line here
";

    #[test]
    fn routes_parse_for_one_iface() {
        let routes = parse_routes(DUMP, "enp5s0");
        assert_eq!(routes.len(), 3, "{routes:?}");
        // default via fe80::6eb:11ff:fe1c:9579
        assert_eq!(routes[0].prefix, 0);
        assert_eq!(routes[0].gateway, Some(v6("fe80::6eb3:11ff:fe1c:9579")));
        // fe80::/64 on-link
        assert_eq!(routes[1].dst, v6("fe80::"));
        assert_eq!(routes[1].prefix, 64);
        assert!(routes[1].gateway.is_none());
        // 2001:569:77ff:b800::/64 on-link
        assert_eq!(routes[2].dst, v6("2001:569:77ff:b800::"));
        // lo's row is not ours
        let lo = parse_routes(DUMP, "lo");
        assert_eq!(lo.len(), 1);
        assert!(lo[0].local);
        assert_eq!(lo[0].dst, v6("::1"));
    }

    #[test]
    fn longest_prefix_match_picks_specificity() {
        let routes = parse_routes(DUMP, "enp5s0");
        // on-link /64 wins over the default for a covered dst
        let r = lookup(&routes, v6("2001:569:77ff:b800::1234")).unwrap();
        assert_eq!(r.prefix, 64);
        assert!(r.gateway.is_none());
        // link-local dst picks fe80::/64
        let r = lookup(&routes, v6("fe80::9999")).unwrap();
        assert_eq!(r.dst, v6("fe80::"));
        // everything else: the default (gateway)
        let r = lookup(&routes, v6("2001:4860:4860::8888")).unwrap();
        assert_eq!(r.prefix, 0);
        assert!(r.gateway.is_some());
        // a dst with no matching default (empty table) → None
        assert!(lookup(&[], v6("::1")).is_none());
    }

    #[test]
    fn hex_addr_and_mask() {
        let a = parse_hex_ipv6("2001056977ffb8000000000000002000").unwrap();
        assert_eq!(a, v6("2001:569:77ff:b800::2000"));
        assert!(parse_hex_ipv6("zz").is_none());
        assert_eq!(
            mask_addr(v6("2001:569:77ff:b800::1234"), 64),
            v6("2001:569:77ff:b800::")
        );
        assert_eq!(mask_addr(v6("::1"), 128), v6("::1"));
        assert_eq!(mask_addr(v6("ffff::1"), 0), Ipv6Addr::UNSPECIFIED);
    }

    #[test]
    fn solicited_node_and_mcast_mac() {
        let sn = solicited_node(v6("2001:db8::1"));
        assert_eq!(sn, v6("ff02::1:ff00:1"));
        assert_eq!(multicast_mac(sn), [0x33, 0x33, 0xff, 0x00, 0x00, 0x01]);
        assert_eq!(
            multicast_mac(v6("ff02::1")),
            [0x33, 0x33, 0x00, 0x00, 0x00, 0x01]
        );
    }

    #[test]
    fn ns_frame_shape_and_checksum() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let src: Ipv6Addr = v6("fe80::aabb:ccdd:eeff");
        let target: Ipv6Addr = v6("fe80::1234");
        let frame = build_ns_frame(mac, src, target, mac);
        // eth: mcast dst mac + iface src + 0x86dd
        assert_eq!(&frame[..6], &multicast_mac(solicited_node(target)));
        assert_eq!(&frame[6..12], &mac);
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), 0x86dd);
        // ipv6: next 58, hop 255, dst = solicited-node (header at 14)
        assert_eq!(frame[14 + 6], 58);
        assert_eq!(frame[14 + 7], 255);
        assert_eq!(
            &frame[14 + 24..14 + 40],
            &solicited_node(target).octets()[..]
        );
        // icmpv6: type NS, target, SLLA
        let icmp_at = 14 + 40;
        assert_eq!(frame[icmp_at], 135);
        assert_eq!(&frame[icmp_at + 8..icmp_at + 24], &target.octets()[..]);
        assert_eq!(frame[icmp_at + 24], 1); // SLLA type
        // checksum verifies against the independent fold
        let mut zeroed = frame[icmp_at..].to_vec();
        zeroed[2] = 0;
        zeroed[3] = 0;
        let found = u16::from_be_bytes([frame[icmp_at + 2], frame[icmp_at + 3]]);
        assert_eq!(found, icmp6_checksum(src, solicited_node(target), &zeroed));
    }

    #[test]
    fn na_parse_roundtrip() {
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let target: Ipv6Addr = v6("2001:db8::1");
        // Handcraft an NA frame (eth + ipv6 + icmpv6 type 136).
        let sn = "fe80::2".parse::<Ipv6Addr>().unwrap();
        let mut icmp = vec![136u8, 0, 0, 0, 0xe0, 0, 0, 0]; // r,s,o flags
        icmp.extend_from_slice(&target.octets());
        let ck = icmp6_checksum(sn, v6("2001:db8::9"), &icmp);
        icmp[2] = ck.to_be_bytes()[0];
        icmp[3] = ck.to_be_bytes()[1];
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0u8; 6]);
        frame.extend_from_slice(&mac);
        frame.extend_from_slice(&0x86ddu16.to_be_bytes());
        frame.extend_from_slice(&[0, 0, 0, 0]);
        frame.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
        frame.extend_from_slice(&[58, 255]);
        frame.extend_from_slice(&sn.octets());
        frame.extend_from_slice(&"2001:db8::9".parse::<Ipv6Addr>().unwrap().octets());
        frame.extend_from_slice(&icmp);
        assert_eq!(parse_na(&frame), Some((target, mac)));
        // not an NA / wrong ethertype → None
        let mut bad = frame.clone();
        bad[12] = 0x08;
        assert!(parse_na(&bad).is_none());
        assert!(parse_na(&frame[..60]).is_none());
    }

    #[test]
    fn cache_resolution_and_fallbacks() {
        let routes = parse_routes(DUMP, "enp5s0");
        let mut cache = NdpCache::new();
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

        // Multicast maps directly.
        let m = cache
            .next_hop_mac(
                &routes,
                v6("ff02::1"),
                mac,
                v6("fe80::1"),
                &mut |_| Ok(()),
                &mut |_| Ok(None),
            )
            .unwrap();
        assert_eq!(m, Some([0x33, 0x33, 0x00, 0x00, 0x00, 0x01]));

        // A local-route dst (lo's ::1 row) keeps the iface-MAC fallback.
        let lo_routes = parse_routes(DUMP, "lo");
        let m = cache
            .next_hop_mac(
                &lo_routes,
                v6("::1"),
                mac,
                v6("::1"),
                &mut |_| Ok(()),
                &mut |_| Ok(None),
            )
            .unwrap();
        assert_eq!(m, None);

        // On-link dst, no neighbor answers: fallback after the NS.
        let mut sent: Vec<Vec<u8>> = Vec::new();
        let dst = v6("fe80::4321");
        let m = cache
            .next_hop_mac(
                &routes,
                dst,
                mac,
                v6("fe80::1"),
                &mut |frame| {
                    sent.push(frame.to_vec());
                    Ok(())
                },
                &mut |_| Ok(None),
            )
            .unwrap();
        assert_eq!(m, None, "no NA: iface-MAC fallback");
        assert_eq!(sent.len(), 1, "one NS went out");
        assert_eq!(sent[0][14 + 40], 135);

        // On-link dst, an NA arrives: cached MAC.
        let target = v6("fe80::5555");
        let na_frame = {
            let mut icmp = vec![136u8, 0, 0, 0, 0, 0, 0, 0];
            icmp.extend_from_slice(&target.octets());
            let mut frame = Vec::new();
            frame.extend_from_slice(&[0u8; 6]);
            let na_mac = [0x22, 0x22, 0x22, 0x22, 0x22, 0x22];
            frame.extend_from_slice(&na_mac);
            frame.extend_from_slice(&0x86ddu16.to_be_bytes());
            frame.extend_from_slice(&[0, 0, 0, 0]);
            frame.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
            frame.extend_from_slice(&[58, 255]);
            frame.extend_from_slice(&"fe80::2".parse::<Ipv6Addr>().unwrap().octets());
            frame.extend_from_slice(&"fe80::9".parse::<Ipv6Addr>().unwrap().octets());
            frame.extend_from_slice(&icmp);
            frame
        };
        let replies = [Ok(Some((na_frame.clone(), 0))), Ok(None)];
        let mut it = replies.into_iter();
        let m = cache
            .next_hop_mac(
                &routes,
                target,
                mac,
                v6("fe80::1"),
                &mut |_| Ok(()),
                &mut |_| it.next().unwrap(),
            )
            .unwrap();
        assert_eq!(m, Some([0x22, 0x22, 0x22, 0x22, 0x22, 0x22]));

        // Cache hit: no NS, no recv.
        let m = cache
            .next_hop_mac(
                &routes,
                target,
                mac,
                v6("fe80::1"),
                &mut |_| panic!("cache hit must not send"),
                &mut |_| panic!("cache hit must not recv"),
            )
            .unwrap();
        assert_eq!(m, Some([0x22, 0x22, 0x22, 0x22, 0x22, 0x22]));

        // A gateway dst resolves the GATEWAY's MAC (default route).
        let gw = v6("fe80::6eb3:11ff:fe1c:9579");
        let na_frame_gw = {
            let mut icmp = vec![136u8, 0, 0, 0, 0, 0, 0, 0];
            icmp.extend_from_slice(&gw.octets());
            let mut frame = Vec::new();
            frame.extend_from_slice(&[0u8; 6]);
            let gmac = [0x33, 0x33, 0x33, 0x33, 0x33, 0x33];
            frame.extend_from_slice(&gmac);
            frame.extend_from_slice(&0x86ddu16.to_be_bytes());
            frame.extend_from_slice(&[0, 0, 0, 0]);
            frame.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
            frame.extend_from_slice(&[58, 255]);
            frame.extend_from_slice(&"fe80::2".parse::<Ipv6Addr>().unwrap().octets());
            frame.extend_from_slice(&"fe80::3".parse::<Ipv6Addr>().unwrap().octets());
            frame.extend_from_slice(&icmp);
            frame
        };
        let replies = [Ok(Some((na_frame_gw, 4)))]; // pkttype outgoing: accepted
        let mut it = replies.into_iter();
        let m = cache
            .next_hop_mac(
                &routes,
                v6("2001:4860:4860::8888"), // off-link
                mac,
                v6("fe80::1"),
                &mut |_| Ok(()),
                &mut |_| it.next().unwrap(),
            )
            .unwrap();
        assert_eq!(m, Some([0x33, 0x33, 0x33, 0x33, 0x33, 0x33]));
    }
}
