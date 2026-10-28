//! NDP option TLV grammar (write side; tranche 17b — the dhcp
//! options-grammar architecture instantiated for RFC 4861 §4.6):
//! `slla:MAC`, `tlla:MAC`, `mtu:N`, `prefix:LEN` with comma
//! continuations (IP, valid, preferred, then bare `l`/`a` flags), and
//! the raw escape `raw:TYPE:HEX`. Option order is preserved; every
//! region is 8-octet TLVs by construction (lengths in 8-byte units).

use wrex_core::EncodeError;
use wrex_core::options::{bad, named, tokens, unknown};

const FIELD: &str = "icmpv6.options";

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

/// The named-option table (the shared `known` gate: a bare
/// continuation may itself contain ':' — an IPv6 address — so only
/// these heads take the named branch).
const KNOWN: &[&str] = &["slla", "tlla", "mtu", "prefix", "raw"];
const GRAMMAR_DOC: &str =
    "slla:MAC, tlla:MAC, mtu:N, prefix:LEN,IP[,valid,preferred][,l][,a], raw:TYPE:HEX";

/// Parse the `--icmpv6-options` list grammar into raw TLV bytes.
pub(crate) fn parse_ndp_options(raw: &str) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    let mut pending = Pending::None;
    for token in tokens(raw) {
        if let Some((name, args)) = named(token, KNOWN) {
            flush(&mut pending, &mut out)?;
            match name {
                "slla" | "tlla" => {
                    let mac: [u8; 6] = args
                        .trim()
                        .split(':')
                        .map(|p| u8::from_str_radix(p, 16).unwrap_or(0))
                        .collect::<Vec<u8>>()
                        .try_into()
                        .map_err(|_| bad(FIELD, format!("bad MAC in `{token}`")))?;
                    let otype = if name == "slla" { 1 } else { 2 };
                    out.extend_from_slice(&[otype, 1]);
                    out.extend_from_slice(&mac);
                }
                "mtu" => {
                    let n: u32 = args
                        .trim()
                        .parse()
                        .map_err(|_| bad(FIELD, format!("bad mtu in `{token}`")))?;
                    out.extend_from_slice(&[5, 1, 0, 0]);
                    out.extend_from_slice(&n.to_be_bytes());
                }
                "prefix" => {
                    let plen: u8 = args
                        .trim()
                        .parse()
                        .map_err(|_| bad(FIELD, format!("bad prefix length in `{token}`")))?;
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
                        .ok_or_else(|| bad(FIELD, format!("raw wants TYPE:HEX in `{token}`")))?;
                    let otype: u8 = t
                        .trim()
                        .parse()
                        .map_err(|_| bad(FIELD, format!("bad option type in `{token}`")))?;
                    let bytes = hex::decode(hex.trim())
                        .map_err(|_| bad(FIELD, format!("bad hex in `{token}`")))?;
                    push_raw(&mut out, otype, &bytes)?;
                }
                _ => unreachable!("the KNOWN list is the dispatch table"),
            }
        } else {
            // Bare continuation tokens feed the open prefix option.
            match &mut pending {
                Pending::None => return Err(unknown(FIELD, token, GRAMMAR_DOC)),
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
                                return Err(bad(
                                    FIELD,
                                    format!("prefix wants one address (`{token}`)"),
                                ));
                            }
                            *addr = Some(ip);
                        } else if let Ok(n) = token.parse::<u32>() {
                            if valid.is_none() {
                                *valid = Some(n);
                            } else if preferred.is_none() {
                                *preferred = Some(n);
                            } else {
                                return Err(bad(
                                    FIELD,
                                    format!("prefix takes two lifetimes (`{token}`)"),
                                ));
                            }
                        } else {
                            return Err(bad(FIELD, format!("bad prefix continuation `{token}`")));
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
    // RFC 4861 §4.6: Length counts 8-octet units of the WHOLE option
    // (type + length + data) — the region, not the payload, sits on
    // the grid. The read side agrees (`olen * 8` spans the header).
    let total = (bytes.len() + 2).div_ceil(8) * 8;
    let units = total / 8;
    if units > 255 {
        return Err(bad(
            FIELD,
            format!("option {otype} region does not fit TLV lengths"),
        ));
    }
    out.extend_from_slice(&[otype, units as u8]);
    out.extend_from_slice(bytes);
    out.resize(out.len() + (total - 2 - bytes.len()), 0);
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
            let addr = addr.ok_or_else(|| bad(FIELD, "prefix wants an address"))?;
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
    const KNOWN: &[&str] = &[
        "include",
        "exclude",
        "to_include",
        "to_exclude",
        "allow",
        "block",
    ];
    for token in tokens(raw) {
        if let Some((name, args)) = named(token, KNOWN) {
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
                .map_err(|_| bad(FIELD, format!("bad multicast address in `{token}`")))?;
            pending = Some((mode, addr, Vec::new()));
        } else if let Ok(ip) = token.parse::<std::net::Ipv6Addr>() {
            match &mut pending {
                Some((_, _, sources)) => sources.push(ip),
                None => return Err(bad(FIELD, format!("dangling source `{token}`"))),
            }
        } else {
            return Err(bad(FIELD, format!("bad record token `{token}`")));
        }
    }
    flush(&mut pending, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `prefix:LEN,ADDR,VALID,PREFERRED,l,a` → one RFC 4861 §4.6.2 TLV.
    fn prefix_tlv(
        plen: u8,
        flags: u8,
        addr: std::net::Ipv6Addr,
        valid: u32,
        preferred: u32,
    ) -> Vec<u8> {
        let mut v = vec![3, 4, plen, flags, 0, 0, 0, 0];
        v.extend_from_slice(&addr.octets());
        v.extend_from_slice(&valid.to_be_bytes());
        v.extend_from_slice(&preferred.to_be_bytes());
        v
    }

    #[test]
    fn ndp_options_slla_tlla_mtu() {
        let out = parse_ndp_options("slla:00:11:22:33:44:55").expect("slla");
        assert_eq!(out, [1, 1, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        let out = parse_ndp_options("tlla:aa:bb:cc:dd:ee:ff").expect("tlla");
        assert_eq!(out, [2, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        // Order preserved across commas; empty tokens skipped.
        let out = parse_ndp_options("slla:00:11:22:33:44:55, ,mtu:1500").expect("slla+mtu");
        assert_eq!(
            out,
            vec![
                1, 1, 0, 0x11, 0x22, 0x33, 0x44, 0x55, // slla
                5, 1, 0, 0, 0, 0, 0x05, 0xdc, // mtu 1500 BE
            ]
        );
    }

    #[test]
    fn ndp_options_prefix_continuations() {
        let addr: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let out =
            parse_ndp_options("prefix:64,2001:db8::1,2592000,604800,l,a").expect("full prefix");
        assert_eq!(out, prefix_tlv(64, 0b1100_0000, addr, 2_592_000, 604_800));
        // Lifetimes optional (default 0); flags optional; bare `a` only.
        let out = parse_ndp_options("prefix:64,2001:db8::1,a").expect("bare a");
        assert_eq!(out, prefix_tlv(64, 0b0100_0000, addr, 0, 0));
        // Address-less lifetimes are fine (addr still required).
        let out = parse_ndp_options("prefix:56,2001:db8::2,100").expect("one lifetime");
        let addr2: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        assert_eq!(out, prefix_tlv(56, 0, addr2, 100, 0));
    }

    #[test]
    fn ndp_options_raw_escape_pads_to_the_grid() {
        // 4 payload bytes: whole region (2 hdr + payload) pads to 8.
        let out = parse_ndp_options("raw:7:00112233").expect("raw pads");
        assert_eq!(out, [7, 1, 0x00, 0x11, 0x22, 0x33, 0, 0]);
        // 8 payload bytes: the region is 10, so it rounds to 16 (units=2).
        let out = parse_ndp_options("raw:1:aabbccddeeff0011").expect("raw grows");
        assert_eq!(
            out,
            [
                1, 2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0, 0, 0, 0, 0, 0
            ]
        );
        // A large escape that cannot fit any TLV length errors out.
        assert!(parse_ndp_options(&format!("raw:7:{}", "00".repeat(2048))).is_err());
    }

    #[test]
    fn ndp_options_errors() {
        // Dangling continuation with no open option (also the unknown-
        // name path: `foo:1` is not a known option, so it lands here).
        assert!(parse_ndp_options("2001:db8::1").is_err());
        assert!(parse_ndp_options("foo:1").is_err());
        // Prefix without an address.
        assert!(parse_ndp_options("prefix:64").is_err());
        // Two addresses on one prefix.
        assert!(parse_ndp_options("prefix:64,2001:db8::1,2001:db8::2").is_err());
        // A third lifetime.
        assert!(parse_ndp_options("prefix:64,2001:db8::1,1,2,3").is_err());
        // Bad continuations.
        assert!(parse_ndp_options("prefix:64,2001:db8::1,nonsense").is_err());
        // Bad mtu / bad prefix length / bad raw forms.
        assert!(parse_ndp_options("mtu:big").is_err());
        assert!(parse_ndp_options("prefix:big").is_err());
        assert!(parse_ndp_options("raw:7").is_err());
        assert!(parse_ndp_options("raw:zz:00").is_err());
        assert!(parse_ndp_options("raw:7:zz").is_err());
        // Bad MAC.
        assert!(parse_ndp_options("slla:zz").is_err());
    }

    #[test]
    fn mld_records_grammar() {
        let a: std::net::Ipv6Addr = "ff02::1".parse().unwrap();
        // One record, no sources: mode, auxlen, srclen(0), addr.
        let mut want = vec![1, 0, 0, 0];
        want.extend_from_slice(&a.octets());
        assert_eq!(parse_mld_records("include:ff02::1").expect("include"), want);
        // Sources as bare continuations; second record flushes the first.
        let s1: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let s2: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        let b: std::net::Ipv6Addr = "ff02::2".parse().unwrap();
        let mut want = vec![4, 0, 0, 2]; // to_exclude
        want.extend_from_slice(&a.octets());
        want.extend_from_slice(&s1.octets());
        want.extend_from_slice(&s2.octets());
        let mut tail = vec![6, 0, 0, 0]; // block
        tail.extend_from_slice(&b.octets());
        want.extend_from_slice(&tail);
        assert_eq!(
            parse_mld_records("to_exclude:ff02::1,2001:db8::1,2001:db8::2,block:ff02::2")
                .expect("two records"),
            want
        );
        // All six modes take their RFC 3810 §5.2 wire values.
        for (name, mode) in [
            ("include", 1u8),
            ("exclude", 2),
            ("to_include", 3),
            ("to_exclude", 4),
            ("allow", 5),
            ("block", 6),
        ] {
            let expr = format!("{name}:ff02::1");
            let got = parse_mld_records(&expr).expect("mode");
            assert_eq!(got[0], mode, "{name} must encode mode {mode}");
        }
    }

    #[test]
    fn mld_records_errors() {
        // Dangling source with no open record.
        assert!(parse_mld_records("2001:db8::1").is_err());
        // Unknown record name → bare token → not an address.
        assert!(parse_mld_records("hello").is_err());
        // Bad address in a known record.
        assert!(parse_mld_records("include:not-an-addr").is_err());
    }
}
