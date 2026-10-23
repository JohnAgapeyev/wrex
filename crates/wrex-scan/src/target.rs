//! Target and port grammar: IPv4/IPv6 addresses, CIDR blocks, inclusive
//! START-END ranges (v4 tail shorthand) and comma lists of ports/ranges.
//! All errors are `String` (mapped to exit-2 usage errors by the CLI).

use std::net::{Ipv4Addr, Ipv6Addr};

/// One scan target address (tranche 7b: family-aware).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ScanAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl ScanAddr {
    pub const fn family(self) -> Family {
        match self {
            ScanAddr::V4(_) => Family::V4,
            ScanAddr::V6(_) => Family::V6,
        }
    }

    pub fn is_unspecified(self) -> bool {
        match self {
            ScanAddr::V4(a) => a.is_unspecified(),
            ScanAddr::V6(a) => a.is_unspecified(),
        }
    }
}

impl std::fmt::Display for ScanAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanAddr::V4(a) => write!(f, "{a}"),
            ScanAddr::V6(a) => write!(f, "{a}"),
        }
    }
}

impl serde::Serialize for ScanAddr {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

/// The address family of a scan (all targets share one family per scan).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    /// The network-layer registry kind probes/craft start from.
    pub const fn ip_kind(self) -> &'static str {
        match self {
            Family::V4 => "ipv4",
            Family::V6 => "ipv6",
        }
    }

    /// The echo protocol kind for this family (scan `icmp` mode).
    pub const fn echo_kind(self) -> &'static str {
        match self {
            Family::V4 => "icmp",
            Family::V6 => "icmpv6",
        }
    }
}

/// Sanity cap on one target spec's expansion (a `/0` would otherwise
/// enumerate 2^32 addresses before the global probe-count guard runs).
pub const MAX_ADDRS_PER_TARGET: u64 = 1 << 20;

/// Parse the repeatable positional TARGET list into a deduplicated,
/// sorted address vector. Every target of one scan must share a family
/// (a mixed list is a usage error — split it into two invocations).
///
/// Each target: `IPv4`/`IPv6`, `CIDR` (`a.b.c.d/prefix`,
/// `2001:db8::/prefix`) or inclusive range `START-END` (both ends full
/// addresses of one family; v4 END may be a tail: `1.2.3.4-e` ==
/// `1.2.3.4-1.2.3.5`, `10.0.0.0-0.255` == `10.0.0.0-10.0.0.255`).
/// IPv4 CIDR blocks with prefix < /31 skip the network and broadcast
/// addresses; IPv6 CIDRs are all-hosts.
pub fn parse_targets(raw: &[String]) -> Result<Vec<ScanAddr>, String> {
    let mut set = std::collections::BTreeSet::new();
    for item in raw {
        for addr in expand_target(item)? {
            set.insert(addr);
        }
    }
    let out: Vec<ScanAddr> = set.into_iter().collect();
    let mut family: Option<Family> = None;
    for a in &out {
        let f = a.family();
        match family {
            None => family = Some(f),
            Some(prev) if prev == f => {}
            Some(prev) => {
                return Err(format!(
                    "mixed address families in targets ({} and {}); run one scan per family",
                    match prev {
                        Family::V4 => "ipv4",
                        Family::V6 => "ipv6",
                    },
                    match f {
                        Family::V4 => "ipv4",
                        Family::V6 => "ipv6",
                    }
                ));
            }
        }
    }
    Ok(out)
}

fn expand_target(item: &str) -> Result<Vec<ScanAddr>, String> {
    let item = item.trim();
    if item.is_empty() {
        return Err("empty target".to_string());
    }
    if let Some((addr, prefix)) = item.split_once('/') {
        return expand_cidr(addr, prefix);
    }
    if let Some((start, end)) = item.split_once('-') {
        return expand_range(start, end, item);
    }
    let addr = parse_scan_addr(item)
        .ok_or_else(|| format!("bad target `{item}` (expected IPv4/IPv6, CIDR or START-END)"))?;
    Ok(vec![addr])
}

/// Parse a bare address of either family (no CIDR/range syntax).
fn parse_scan_addr(raw: &str) -> Option<ScanAddr> {
    let raw = raw.trim();
    if raw.contains(':') {
        raw.parse::<Ipv6Addr>().ok().map(ScanAddr::V6)
    } else {
        raw.parse::<Ipv4Addr>().ok().map(ScanAddr::V4)
    }
}

fn guard_count(count: u64, item: &str) -> Result<(), String> {
    if count > MAX_ADDRS_PER_TARGET {
        return Err(format!(
            "target `{item}` expands to {count} addresses (> {MAX_ADDRS_PER_TARGET})"
        ));
    }
    Ok(())
}

fn expand_cidr(addr_raw: &str, prefix_raw: &str) -> Result<Vec<ScanAddr>, String> {
    let addr = parse_scan_addr(addr_raw).ok_or_else(|| {
        format!("bad CIDR address `{addr_raw}` (expected an IPv4 or IPv6 address)")
    })?;
    let prefix: u32 = prefix_raw
        .trim()
        .parse()
        .map_err(|_| format!("bad CIDR prefix `{prefix_raw}`"))?;
    match addr {
        ScanAddr::V4(a) => {
            if prefix > 32 {
                return Err(format!("bad CIDR prefix `{prefix_raw}` (> 32)"));
            }
            let host_bits = 32 - prefix;
            let count = 1u64 << host_bits;
            guard_count(count, &format!("{addr_raw}/{prefix_raw}"))?;
            let base = u32::from(a) & mask_of(prefix);
            // /31 and /32 are all-hosts (RFC 3021); shorter prefixes skip
            // network + broadcast.
            let skip_ends = prefix < 31;
            let first = if skip_ends { 1 } else { 0 };
            let last_exclusive = if skip_ends { count - 1 } else { count };
            Ok((first..last_exclusive)
                .map(|i| ScanAddr::V4(Ipv4Addr::from(base + (i as u32))))
                .collect())
        }
        ScanAddr::V6(a) => {
            if prefix > 128 {
                return Err(format!("bad CIDR prefix `{prefix_raw}` (> 128)"));
            }
            let host_bits = 128 - prefix;
            // Shift-overflow-safe count: >= 64 host bits always exceeds
            // the per-target cap (guard_count rejects it below).
            let count = if host_bits >= 64 {
                u128::MAX
            } else {
                1u128 << host_bits
            };
            guard_count(count as u64, &format!("{addr_raw}/{prefix_raw}"))?;
            let base = u128::from_be_bytes(a.octets()) & mask6_of(prefix);
            Ok((0..count)
                .map(|i| ScanAddr::V6(Ipv6Addr::from((base + i).to_be_bytes())))
                .collect())
        }
    }
}

const fn mask_of(prefix: u32) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

const fn mask6_of(prefix: u32) -> u128 {
    if prefix == 0 {
        0
    } else if prefix >= 128 {
        u128::MAX
    } else {
        // (const: unwrap_or is not const-callable — spelled out.)
        match u128::MAX.checked_shl(128 - prefix) {
            Some(m) => m,
            None => 0,
        }
    }
}

fn expand_range(start_raw: &str, end_raw: &str, item: &str) -> Result<Vec<ScanAddr>, String> {
    let start = parse_scan_addr(start_raw).ok_or_else(|| {
        format!("bad range start in `{item}` (expected a full IPv4/IPv6 address)")
    })?;
    match start {
        ScanAddr::V4(start4) => {
            let start_u32 = u32::from(start4);
            // End: a full address, or a tail whose dot-parts complete the
            // start's leading octets (v4 shorthand only).
            let end_u32 = match end_raw.trim().parse::<Ipv4Addr>() {
                Ok(end) => u32::from(end),
                Err(_) => {
                    let parts: Vec<&str> = end_raw.trim().split('.').collect();
                    if parts.is_empty() || parts.len() > 3 || parts.iter().any(|p| p.is_empty()) {
                        return Err(format!("bad range end `{end_raw}` in `{item}`"));
                    }
                    let start_octets = start4.octets();
                    let mut octets = [0u8; 4];
                    let lead = 4 - parts.len();
                    octets[..lead].copy_from_slice(&start_octets[..lead]);
                    for (i, p) in parts.iter().enumerate() {
                        octets[lead + i] = p
                            .parse::<u8>()
                            .map_err(|_| format!("bad range end `{end_raw}` in `{item}`"))?;
                    }
                    u32::from(Ipv4Addr::from(octets))
                }
            };
            if start_u32 > end_u32 {
                return Err(format!(
                    "bad range `{item}`: start {} > end {}",
                    start4,
                    end_raw.trim()
                ));
            }
            let count = (end_u32 - start_u32 + 1) as u64;
            guard_count(count, item)?;
            Ok((start_u32..=end_u32)
                .map(|v| ScanAddr::V4(Ipv4Addr::from(v)))
                .collect())
        }
        // v6 ranges: both ends must be full addresses (no tail shorthand).
        ScanAddr::V6(start6) => {
            let end6: Ipv6Addr = end_raw.trim().parse().map_err(|_| {
                format!("bad range end `{end_raw}` in `{item}` (v6 ends are full addresses)")
            })?;
            let s = u128::from_be_bytes(start6.octets());
            let e = u128::from_be_bytes(end6.octets());
            if s > e {
                return Err(format!("bad range `{item}`: start {start6} > end {end6}"));
            }
            let count = (e - s + 1) as u64;
            guard_count(count, item)?;
            Ok((s..=e)
                .map(|v| ScanAddr::V6(Ipv6Addr::from(v.to_be_bytes())))
                .collect())
        }
    }
}

/// Parse a `--ports SPEC` comma list (`22,80,100-200`) into a
/// deduplicated, sorted port vector. Port values are `1..=65535`.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut set = std::collections::BTreeSet::new();
    for item in spec.split(',') {
        let item = item.trim();
        if item.is_empty() {
            return Err("empty port in list".to_string());
        }
        let (lo, hi) = match item.split_once('-') {
            Some((a, b)) => (a.trim(), b.trim()),
            None => (item, item),
        };
        let lo: u32 = lo.parse().map_err(|_| format!("bad port `{item}`"))?;
        let hi: u32 = hi.parse().map_err(|_| format!("bad port `{item}`"))?;
        if !(1..=65535).contains(&lo) || !(1..=65535).contains(&hi) {
            return Err(format!("port `{item}` out of range (1..=65535)"));
        }
        if lo > hi {
            return Err(format!("bad port range `{item}` (start > end)"));
        }
        for p in lo..=hi {
            set.insert(p as u16);
        }
    }
    Ok(set.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> ScanAddr {
        ScanAddr::V4(s.parse().unwrap())
    }

    fn v6(s: &str) -> ScanAddr {
        ScanAddr::V6(s.parse().unwrap())
    }

    #[test]
    fn single_and_dedup() {
        let v =
            parse_targets(&["127.0.0.1".into(), "127.0.0.1".into(), "10.0.0.5".into()]).unwrap();
        assert_eq!(v, vec![v4("10.0.0.5"), v4("127.0.0.1")]);
        let v = parse_targets(&["::1".into(), "::1".into(), "fe80::1".into()]).unwrap();
        assert_eq!(v, vec![v6("::1"), v6("fe80::1")]);
    }

    #[test]
    fn mixed_families_rejected() {
        let e = parse_targets(&["127.0.0.1".into(), "::1".into()]).unwrap_err();
        assert!(e.contains("mixed address families"), "{e}");
    }

    #[test]
    fn cidr_skips_network_and_broadcast() {
        let v = parse_targets(&["10.0.0.0/30".into()]).unwrap();
        let got: Vec<String> = v.iter().map(|a| a.to_string()).collect();
        assert_eq!(got, vec!["10.0.0.1", "10.0.0.2"]);
    }

    #[test]
    fn cidr_31_32_all_hosts() {
        assert_eq!(parse_targets(&["10.0.0.0/31".into()]).unwrap().len(), 2);
        assert_eq!(parse_targets(&["10.0.0.7/32".into()]).unwrap().len(), 1);
        assert_eq!(parse_targets(&["10.1.0.0/24".into()]).unwrap().len(), 254);
    }

    #[test]
    fn v6_cidr() {
        assert_eq!(parse_targets(&["2001:db8::/126".into()]).unwrap().len(), 4);
        assert_eq!(parse_targets(&["::1/128".into()]).unwrap().len(), 1);
        // all-hosts (no network/broadcast skipping in v6)
        assert_eq!(parse_targets(&["fe80::/124".into()]).unwrap().len(), 16);
        let e = parse_targets(&["::/0".into()]).unwrap_err();
        assert!(e.contains("expands to"), "{e}");
    }

    #[test]
    fn ranges_full_and_tail() {
        let v = parse_targets(&["10.0.0.1-10.0.0.3".into()]).unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v.first().unwrap().to_string(), "10.0.0.1");
        assert_eq!(v.last().unwrap().to_string(), "10.0.0.3");
        // tail shorthand (decimal)
        let v = parse_targets(&["1.2.3.4-5".into()]).unwrap();
        assert_eq!(
            v.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
            vec!["1.2.3.4", "1.2.3.5"]
        );
        let v = parse_targets(&["10.0.0.0-0.255".into()]).unwrap();
        assert_eq!(v.len(), 256);
        assert_eq!(v.last().unwrap().to_string(), "10.0.0.255");
        // v6 ranges: full addresses only
        let v = parse_targets(&["::1-::4".into()]).unwrap();
        assert_eq!(v.len(), 4);
        assert_eq!(v.last().unwrap().to_string(), "::4");
        // v6 tail shorthand is rejected
        assert!(parse_targets(&["::1-4".into()]).is_err());
    }

    #[test]
    fn target_errors() {
        assert!(parse_targets(&["999.0.0.1".into()]).is_err());
        assert!(parse_targets(&["10.0.0.0/33".into()]).is_err());
        assert!(parse_targets(&["2001:db8::/129".into()]).is_err());
        assert!(parse_targets(&["10.0.0.0/0".into()]).is_err()); // exceeds per-target cap
        assert!(parse_targets(&["10.0.0.5-10.0.0.1".into()]).is_err()); // start > end
        assert!(parse_targets(&["::5-::1".into()]).is_err()); // v6 start > end
        assert!(parse_targets(&["10.0.0.1-".into()]).is_err());
        assert!(parse_targets(&["-10.0.0.1".into()]).is_err());
        assert!(parse_targets(&["10.0.0.a-b".into()]).is_err());
        // tail shorthand is decimal, not hex
        assert!(parse_targets(&["1.2.3.4-e".into()]).is_err());
        assert!(parse_targets(&["".into()]).is_err());
    }

    #[test]
    fn ports_grammar() {
        let v = parse_ports("22, 80,100-102,22").unwrap();
        assert_eq!(v, vec![22, 80, 100, 101, 102]);
        assert_eq!(parse_ports("1").unwrap().len(), 1);
        assert_eq!(parse_ports("65535").unwrap().len(), 1);
    }

    #[test]
    fn port_errors() {
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("65536").is_err());
        assert!(parse_ports("100-50").is_err());
        assert!(parse_ports("abc").is_err());
        assert!(parse_ports("1,,2").is_err());
        assert!(parse_ports("").is_err());
    }

    #[test]
    fn scan_addr_serde_and_family() {
        assert_eq!(v4("10.0.0.1").family(), Family::V4);
        assert_eq!(v6("::1").family(), Family::V6);
        assert_eq!(Family::V4.ip_kind(), "ipv4");
        assert_eq!(Family::V6.ip_kind(), "ipv6");
        assert_eq!(Family::V4.echo_kind(), "icmp");
        assert_eq!(Family::V6.echo_kind(), "icmpv6");
        let j = serde_json::to_value(v6("2001:db8::1")).unwrap();
        assert_eq!(j, "2001:db8::1");
        let j = serde_json::to_value(v4("10.0.0.1")).unwrap();
        assert_eq!(j, "10.0.0.1");
        assert!(v6("::").is_unspecified());
    }
}
