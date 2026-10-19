//! Target and port grammar: IPv4 addresses, CIDR blocks, inclusive
//! START-END ranges (with tail shorthand) and comma lists of
//! ports/ranges. All errors are `String` (mapped to exit-2 usage
//! errors by the CLI).

use std::net::Ipv4Addr;

/// Sanity cap on one target spec's expansion (a `/0` would otherwise
/// enumerate 2^32 addresses before the global probe-count guard runs).
pub const MAX_ADDRS_PER_TARGET: u64 = 1 << 20;

/// Parse the repeatable positional TARGET list into a deduplicated,
/// sorted address vector.
///
/// Each target: `IPv4`, `CIDR` (`a.b.c.d/prefix`) or inclusive range
/// `START-END` (END may be a full address or a tail: `1.2.3.4-e` ==
/// `1.2.3.4-1.2.3.5`, `10.0.0.0-0.255` == `10.0.0.0-10.0.0.255`).
/// CIDR blocks with prefix < /31 skip the network and broadcast
/// addresses.
pub fn parse_targets(raw: &[String]) -> Result<Vec<Ipv4Addr>, String> {
    let mut set = std::collections::BTreeSet::new();
    for item in raw {
        for addr in expand_target(item)? {
            set.insert(addr);
        }
    }
    Ok(set.into_iter().collect())
}

fn expand_target(item: &str) -> Result<Vec<Ipv4Addr>, String> {
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
    let addr: Ipv4Addr = item
        .parse()
        .map_err(|_| format!("bad target `{item}` (expected IPv4, CIDR or START-END)"))?;
    Ok(vec![addr])
}

fn expand_cidr(addr_raw: &str, prefix_raw: &str) -> Result<Vec<Ipv4Addr>, String> {
    let addr: Ipv4Addr = addr_raw
        .trim()
        .parse()
        .map_err(|_| format!("bad CIDR address `{addr_raw}`"))?;
    let prefix: u32 = prefix_raw
        .trim()
        .parse()
        .map_err(|_| format!("bad CIDR prefix `{prefix_raw}`"))?;
    if prefix > 32 {
        return Err(format!("bad CIDR prefix `{prefix_raw}` (> 32)"));
    }
    let host_bits = 32 - prefix;
    let count = 1u64 << host_bits;
    if count > MAX_ADDRS_PER_TARGET {
        return Err(format!(
            "target `{}/{prefix}` expands to {count} addresses (> {})",
            MAX_ADDRS_PER_TARGET, MAX_ADDRS_PER_TARGET
        ));
    }
    let base = u32::from(addr) & mask_of(prefix);
    // /31 and /32 are all-hosts (RFC 3021); shorter prefixes skip
    // network + broadcast.
    let skip_ends = prefix < 31;
    let first = if skip_ends { 1 } else { 0 };
    let last_exclusive = if skip_ends { count - 1 } else { count };
    Ok((first..last_exclusive)
        .map(|i| Ipv4Addr::from(base + (i as u32)))
        .collect())
}

fn mask_of(prefix: u32) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn expand_range(start_raw: &str, end_raw: &str, item: &str) -> Result<Vec<Ipv4Addr>, String> {
    let start: Ipv4Addr = start_raw
        .trim()
        .parse()
        .map_err(|_| format!("bad range start in `{item}`"))?;
    let start_u32 = u32::from(start);
    // End: a full address, or a tail whose dot-parts complete the
    // start's leading octets.
    let end_u32 = match end_raw.trim().parse::<Ipv4Addr>() {
        Ok(end) => u32::from(end),
        Err(_) => {
            let parts: Vec<&str> = end_raw.trim().split('.').collect();
            if parts.is_empty() || parts.len() > 3 || parts.iter().any(|p| p.is_empty()) {
                return Err(format!("bad range end `{end_raw}` in `{item}`"));
            }
            let start_octets = start.octets();
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
            start,
            end_raw.trim()
        ));
    }
    let count = (end_u32 - start_u32 + 1) as u64;
    if count > MAX_ADDRS_PER_TARGET {
        return Err(format!(
            "range `{item}` expands to {count} addresses (> {})",
            MAX_ADDRS_PER_TARGET
        ));
    }
    Ok((start_u32..=end_u32).map(Ipv4Addr::from).collect())
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

    #[test]
    fn single_and_dedup() {
        let v =
            parse_targets(&["127.0.0.1".into(), "127.0.0.1".into(), "10.0.0.5".into()]).unwrap();
        let want: Vec<Ipv4Addr> = vec!["10.0.0.5".parse().unwrap(), "127.0.0.1".parse().unwrap()];
        assert_eq!(v, want);
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
        // /24 → 254 hosts
        assert_eq!(parse_targets(&["10.1.0.0/24".into()]).unwrap().len(), 254);
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
    }

    #[test]
    fn target_errors() {
        assert!(parse_targets(&["999.0.0.1".into()]).is_err());
        assert!(parse_targets(&["10.0.0.0/33".into()]).is_err());
        assert!(parse_targets(&["10.0.0.0/0".into()]).is_err()); // exceeds per-target cap
        assert!(parse_targets(&["10.0.0.5-10.0.0.1".into()]).is_err()); // start > end
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
}
