//! NDP option TLV grammar (write side; tranche 17b — the dhcp
//! options-grammar architecture instantiated for RFC 4861 §4.6):
//! `slla:MAC`, `tlla:MAC`, `mtu:N`, `prefix:LEN` with comma
//! continuations (IP, valid, preferred, then bare `l`/`a` flags), and
//! the raw escape `raw:TYPE:HEX`. Option order is preserved; every
//! region is 8-octet TLVs by construction (lengths in 8-byte units).

use wrex_core::error::EncodeError;

fn bad(msg: String) -> EncodeError {
    EncodeError::IncompatibleStack {
        detail: format!("icmpv6.options: {msg}"),
    }
}

enum Pending {
    None,
    Prefix {
        prefix_len: u8,
        addr: Option<std::net::Ipv6Addr>,
        valid: Option<u32>,
        preferred: Option<u32>,
        l: bool,
        a: bool,
    },
}

/// Parse the `--icmpv6-options` list grammar into raw TLV bytes.
pub(crate) fn parse_ndp_options(raw: &str) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    let mut pending = Pending::None;
    for token in raw.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        // NB: a bare continuation may itself contain ':' (an IPv6
        // address: `prefix:64,2001:db8::1,…`) — only the known option
        // names take the named branch, everything else feeds the open
        // option.
        let known = matches!(
            token.split_once(':').map(|(n, _)| n),
            Some("slla" | "tlla" | "mtu" | "prefix" | "raw")
        );
        if let (true, Some((name, args))) = (known, token.split_once(':')) {
            flush(&mut pending, &mut out)?;
            match name {
                "slla" | "tlla" => {
                    let mac: [u8; 6] = args
                        .trim()
                        .split(':')
                        .map(|p| u8::from_str_radix(p, 16).unwrap_or(0))
                        .collect::<Vec<u8>>()
                        .try_into()
                        .map_err(|_| bad(format!("bad MAC in `{token}`")))?;
                    let otype = if name == "slla" { 1 } else { 2 };
                    out.extend_from_slice(&[otype, 1]);
                    out.extend_from_slice(&mac);
                }
                "mtu" => {
                    let n: u32 = args
                        .trim()
                        .parse()
                        .map_err(|_| bad(format!("bad mtu in `{token}`")))?;
                    out.extend_from_slice(&[5, 1, 0, 0]);
                    out.extend_from_slice(&n.to_be_bytes());
                }
                "prefix" => {
                    let plen: u8 = args
                        .trim()
                        .parse()
                        .map_err(|_| bad(format!("bad prefix length in `{token}`")))?;
                    pending = Pending::Prefix {
                        prefix_len: plen,
                        addr: None,
                        valid: None,
                        preferred: None,
                        l: false,
                        a: false,
                    };
                }
                "raw" => {
                    let (t, hex) = args
                        .split_once(':')
                        .ok_or_else(|| bad(format!("raw wants TYPE:HEX in `{token}`")))?;
                    let otype: u8 = t
                        .trim()
                        .parse()
                        .map_err(|_| bad(format!("bad option type in `{token}`")))?;
                    let bytes = hex::decode(hex.trim())
                        .map_err(|_| bad(format!("bad hex in `{token}`")))?;
                    push_raw(&mut out, otype, &bytes)?;
                }
                other => return Err(bad(format!("unknown option `{other}`"))),
            }
        } else {
            // Bare continuation tokens feed the open prefix option.
            match &mut pending {
                Pending::None => return Err(bad(format!("dangling token `{token}`"))),
                Pending::Prefix {
                    addr,
                    valid,
                    preferred,
                    l,
                    a,
                    ..
                } => match token {
                    "l" => *l = true,
                    "a" => *a = true,
                    _ => {
                        if let Ok(ip) = token.parse::<std::net::Ipv6Addr>() {
                            if addr.is_some() {
                                return Err(bad(format!("prefix wants one address (`{token}`)")));
                            }
                            *addr = Some(ip);
                        } else if let Ok(n) = token.parse::<u32>() {
                            if valid.is_none() {
                                *valid = Some(n);
                            } else if preferred.is_none() {
                                *preferred = Some(n);
                            } else {
                                return Err(bad(format!("prefix takes two lifetimes (`{token}`)")));
                            }
                        } else {
                            return Err(bad(format!("bad prefix continuation `{token}`")));
                        }
                    }
                },
            }
        }
    }
    flush(&mut pending, &mut out)?;
    Ok(out)
}

/// One 8-octet-unit TLV: pad the region up to the grid (the craft
/// rule; lengths count 8-byte units).
fn push_raw(out: &mut Vec<u8>, otype: u8, bytes: &[u8]) -> Result<(), EncodeError> {
    let total = bytes.len().div_ceil(8) * 8;
    let units = total / 8;
    if units == 0 || units > 255 {
        return Err(bad(format!(
            "option {otype} region does not fit TLV lengths"
        )));
    }
    out.extend_from_slice(&[otype, units as u8]);
    out.extend_from_slice(bytes);
    out.resize(out.len() + (total - bytes.len()), 0);
    Ok(())
}

fn flush(pending: &mut Pending, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    match std::mem::replace(pending, Pending::None) {
        Pending::None => Ok(()),
        Pending::Prefix {
            prefix_len,
            addr,
            valid,
            preferred,
            l,
            a,
        } => {
            let addr = addr.ok_or_else(|| bad("prefix wants an address".into()))?;
            // RFC 4861 §4.6.2: type 3, len 4 — plen, flags (L 0x80 |
            // A 0x40), 4 reserved, addr(16), valid(4), preferred(4).
            out.extend_from_slice(&[3, 4, prefix_len, (l as u8) << 7 | (a as u8) << 6]);
            out.extend_from_slice(&[0; 4]);
            out.extend_from_slice(&addr.octets());
            out.extend_from_slice(&valid.unwrap_or(0).to_be_bytes());
            out.extend_from_slice(&preferred.unwrap_or(0).to_be_bytes());
            Ok(())
        }
    }
}

/// The MLDv2 report record grammar (tranche 17b, RFC 3810 §5.2): one
/// token per multicast-address record — `include:ADDR`, `exclude:ADDR`,
/// `to_include:ADDR`, `to_exclude:ADDR`, `allow:ADDR`, `block:ADDR` —
/// with bare IPv6 continuations as the record's sources (the pending
/// architecture). Returns the records region (no 4-byte prefix).
pub(crate) fn parse_mld_records(raw: &str) -> Result<Vec<u8>, EncodeError> {
    #[derive(Clone, Copy)]
    enum Mode {
        // RFC 3810 §5.2 record types — the wire values ARE the
        // discriminants (a 0-based enum wrote mode 1 for exclude).
        Include = 1,
        Exclude = 2,
        ToInclude = 3,
        ToExclude = 4,
        Allow = 5,
        Block = 6,
    }
    let mut out = Vec::new();
    let mut pending: Option<(Mode, std::net::Ipv6Addr, Vec<std::net::Ipv6Addr>)> = None;
    let flush = |pending: &mut Option<(Mode, std::net::Ipv6Addr, Vec<std::net::Ipv6Addr>)>,
                 out: &mut Vec<u8>|
     -> Result<(), EncodeError> {
        if let Some((mode, addr, sources)) = pending.take() {
            out.push(mode as u8);
            out.push(0); // aux data len
            out.extend_from_slice(&(sources.len() as u16).to_be_bytes());
            out.extend_from_slice(&addr.octets());
            for s in sources {
                out.extend_from_slice(&s.octets());
            }
        }
        Ok(())
    };
    for token in raw.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        let known = matches!(
            token.split_once(':').map(|(n, _)| n),
            Some("include" | "exclude" | "to_include" | "to_exclude" | "allow" | "block")
        );
        if let (true, Some((name, args))) = (known, token.split_once(':')) {
            flush(&mut pending, &mut out)?;
            let mode = match name {
                "include" => Mode::Include,
                "exclude" => Mode::Exclude,
                "to_include" => Mode::ToInclude,
                "to_exclude" => Mode::ToExclude,
                "allow" => Mode::Allow,
                _ => Mode::Block,
            };
            let addr: std::net::Ipv6Addr = args
                .trim()
                .parse()
                .map_err(|_| bad(format!("bad multicast address in `{token}`")))?;
            pending = Some((mode, addr, Vec::new()));
        } else if let Ok(ip) = token.parse::<std::net::Ipv6Addr>() {
            match &mut pending {
                Some((_, _, sources)) => sources.push(ip),
                None => return Err(bad(format!("dangling source `{token}`"))),
            }
        } else {
            return Err(bad(format!("bad record token `{token}`")));
        }
    }
    flush(&mut pending, &mut out)?;
    Ok(out)
}
