//! DHCPv6 options value grammar (write side; RFC 8415 §21 TLVs).
//!
//! Comma list of `client_id:HEX`, `server_id:HEX`, `ia_na:IAID[,t1,t2]`,
//! `ia_addr:IP[,preferred,valid]`, `oro:N[,N…]`, `dns:IP[,IP…]`,
//! `domain:NAME`, `elapsed:N`, `rapid`, or the raw escape
//! `hex:CODE:HEX`. Multi-value options (`oro`, `dns`) share the
//! top-level comma with the item separator, so bare numbers/addresses
//! continue the previous option (the dhcp/ip/tcp pending-continuation
//! architecture). `ia_addr` continues the pending `ia_na` as a nested
//! IAADDR sub-option (RFC 8415 §21.4/§21.6 — the first nested use of
//! the record grammar).

use std::net::Ipv6Addr;

use wrex_core::EncodeError;
use wrex_core::options::{bad, named, tokens, unknown};

// Option codes (RFC 8415 registry).
pub const OPT_CLIENT_ID: u16 = 1;
pub const OPT_SERVER_ID: u16 = 2;
pub const OPT_IA_NA: u16 = 3;
pub const OPT_IA_ADDR: u16 = 5;
pub const OPT_ORO: u16 = 6;
pub const OPT_ELAPSED_TIME: u16 = 8;
pub const OPT_RAPID_COMMIT: u16 = 14;
pub const OPT_DNS_SERVERS: u16 = 23;
pub const OPT_DOMAIN_LIST: u16 = 24;

/// DHCPv6 message types (RFC 8415 §7.3 registry). The relay pair is
/// named too — the write side rejects them (relay crafting deferred),
/// the read side dissects their 34-byte extended header.
pub const MSG_TYPES: [(&str, u8); 13] = [
    ("solicit", 1),
    ("advertise", 2),
    ("request", 3),
    ("confirm", 4),
    ("renew", 5),
    ("rebind", 6),
    ("reply", 7),
    ("release", 8),
    ("decline", 9),
    ("reconfigure", 10),
    ("info_req", 11),
    ("relay_forward", 12),
    ("relay_reply", 13),
];

/// Parse a message-type name (`solicit`) or number (`1`).
pub fn parse_msg_type(raw: &str) -> Option<u8> {
    let raw = raw.trim();
    for (name, n) in MSG_TYPES {
        if raw.eq_ignore_ascii_case(name) {
            return Some(n);
        }
    }
    let n: u8 = raw.parse().ok()?;
    (1..=13).contains(&n).then_some(n)
}

/// Canonical lowercase name for a message type (numbers outside the
/// registry render as their decimal form).
pub fn render_msg_type(v: u8) -> String {
    for (name, n) in MSG_TYPES {
        if v == n {
            return name.to_string();
        }
    }
    v.to_string()
}

/// Encode one DNS name in RFC 1035 label form (`wrex.example` →
/// `[4]wrex[7]example[0]`) — the wire format of the domain-search-list
/// option (RFC 8415 §21.15 inherits RFC 3646).
pub fn encode_domain_name(name: &str) -> Result<Vec<u8>, EncodeError> {
    if name.is_empty() {
        return Err(bad(FIELD, "domain: empty name"));
    }
    let mut out = Vec::new();
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(bad(FIELD, format!("domain: bad label in `{name}`")));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0); // root
    Ok(out)
}

/// Decode the label-encoded name list of a domain-search-list option:
/// one or more names, each root-terminated. Names join with `,` —
/// the dissection `text` rendering.
pub fn decode_domain_names(data: &[u8]) -> Option<String> {
    let mut names = Vec::new();
    let mut cursor = 0usize;
    while cursor < data.len() {
        if data[cursor] == 0 {
            cursor += 1;
            continue;
        }
        let mut name = Vec::new();
        loop {
            if cursor >= data.len() {
                return None; // dangling label
            }
            let llen = data[cursor] as usize;
            if llen == 0 {
                cursor += 1;
                break;
            }
            if cursor + 1 + llen > data.len() {
                return None; // overrunning label
            }
            if !name.is_empty() {
                name.push(b'.');
            }
            name.extend_from_slice(&data[cursor + 1..cursor + 1 + llen]);
            cursor += 1 + llen;
        }
        names.push(String::from_utf8_lossy(&name).into_owned());
    }
    if names.is_empty() {
        return None;
    }
    Some(names.join(","))
}

enum Pending {
    None,
    /// Option-request list (oro).
    Codes {
        list: Vec<u16>,
    },
    /// DNS recursive name servers (23).
    Dns {
        ips: Vec<Ipv6Addr>,
    },
    /// Identity-association (IA_NA) — `ia_addr` continuations nest as
    /// IAADDR sub-options inside the IA_NA payload; bare u32s before
    /// any `ia_addr` set t1/t2 (the fixed-part lifetimes).
    Iana(PendingIana),
}

/// The pending IA_NA's accumulators.
pub(crate) struct PendingIana {
    iaid: u32,
    t1: Option<u32>,
    t2: Option<u32>,
    subs: Vec<u8>,
    open_addr: Option<OpenAddr>,
}

/// A half-built IAADDR sub-option: the address plus its optional
/// lifetimes (preferred first, then valid — one bare u32 each).
struct OpenAddr {
    addr: Ipv6Addr,
    preferred: Option<u32>,
    valid: Option<u32>,
}

impl OpenAddr {
    fn tlv(&self) -> Result<Vec<u8>, EncodeError> {
        let mut data = Vec::with_capacity(24);
        data.extend_from_slice(&self.addr.octets());
        data.extend_from_slice(&self.preferred.unwrap_or(0).to_be_bytes());
        data.extend_from_slice(&self.valid.unwrap_or(0).to_be_bytes());
        let mut tlv = Vec::with_capacity(4 + data.len());
        push_tlv(&mut tlv, OPT_IA_ADDR, &data)?;
        Ok(tlv)
    }
}

const FIELD: &str = "dhcp6.options";
const KNOWN: &[&str] = &[
    "client_id",
    "server_id",
    "ia_na",
    "ia_addr",
    "oro",
    "dns",
    "domain",
    "elapsed",
    "hex",
];

/// Push one u16-code/u16-len TLV (the shared skeleton's dhcp6 shape).
fn push_tlv(out: &mut Vec<u8>, code: u16, data: &[u8]) -> Result<(), EncodeError> {
    wrex_core::options::push_tlv_u16(FIELD, out, code, data)
}

/// Open a new IAADDR sub-option inside a pending IA_NA: flush any
/// half-built one into the sub-region first, then start `IP`.
fn open_iaaddr(iana: &mut PendingIana, args: &str, token: &str) -> Result<(), EncodeError> {
    flush_open_addr(iana)?;
    let addr: Ipv6Addr = args
        .trim()
        .parse()
        .map_err(|_| bad(FIELD, format!("bad address in `{token}`")))?;
    iana.open_addr = Some(OpenAddr {
        addr,
        preferred: None,
        valid: None,
    });
    Ok(())
}

/// Fold the half-built IAADDR (if any) into the pending IA_NA's
/// sub-region.
fn flush_open_addr(iana: &mut PendingIana) -> Result<(), EncodeError> {
    if let Some(open) = iana.open_addr.take() {
        iana.subs.extend_from_slice(&open.tlv()?);
    }
    Ok(())
}

fn push_hex(out: &mut Vec<u8>, code: u16, args: &str) -> Result<(), EncodeError> {
    let hexpart = args.strip_prefix("hex:").unwrap_or(args);
    let bytes = wrex_core::value::parse_hex_bytes(hexpart.trim())
        .map_err(|e| bad(FIELD, format!("bad hex: {e}")))?;
    push_tlv(out, code, &bytes)
}

const GRAMMAR_DOC: &str = "valid: client_id:HEX, server_id:HEX, ia_na:IAID[,t1,t2], \
ia_addr:IP[,preferred,valid], oro:N…, dns:IP…, domain:NAME, elapsed:N, rapid, hex:CODE:HEX";

/// Parse the options grammar into raw TLV bytes (u16 code, u16 len).
/// DHCPv6 has no end marker — the region is the message tail.
pub(crate) fn parse_options(raw: &str) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    let mut pending = Pending::None;
    for token in tokens(raw) {
        if let Some((name, args)) = named(token, KNOWN) {
            match name {
                // ia_addr continues the pending IA_NA — it must NOT
                // flush it (IAADDR nests inside the IA_NA payload).
                "ia_addr" => match &mut pending {
                    Pending::Iana(iana) => open_iaaddr(iana, args, token)?,
                    _ => {
                        return Err(bad(
                            FIELD,
                            format!("ia_addr without a pending ia_na (`{token}`)"),
                        ));
                    }
                },
                _ => {
                    flush(&mut pending, &mut out)?;
                    parse_named(&mut out, name, args, token, &mut pending)?;
                }
            }
        } else {
            // Continuation tokens: bare u16s extend oro, bare
            // addresses extend dns; a pending ia_na routes bare u32s
            // to t1/t2 — or, with an open ia_addr, to its lifetimes
            // (preferred first, then valid). `rapid` needs no pending.
            let parsed_u32 = token.parse::<u32>();
            match (&mut pending, token.parse::<u16>()) {
                (Pending::Codes { list }, Ok(n)) => list.push(n),
                (Pending::Dns { ips }, _) if token.parse::<Ipv6Addr>().is_ok() => {
                    ips.push(token.parse::<Ipv6Addr>().unwrap());
                }
                (
                    Pending::Iana(PendingIana {
                        t1,
                        t2,
                        open_addr: Some(open),
                        ..
                    }),
                    _,
                ) if parsed_u32.is_ok() => fill_addr_lifetime(open, parsed_u32.unwrap(), token)?,
                (
                    Pending::Iana(PendingIana {
                        t1,
                        t2,
                        open_addr: None,
                        ..
                    }),
                    _,
                ) if parsed_u32.is_ok() => {
                    let n = parsed_u32.unwrap();
                    if t1.is_none() {
                        *t1 = Some(n);
                    } else if t2.is_none() {
                        *t2 = Some(n);
                    } else {
                        return Err(unknown(FIELD, token, GRAMMAR_DOC));
                    }
                }
                _ => {
                    flush(&mut pending, &mut out)?;
                    match token {
                        "rapid" => push_tlv(&mut out, OPT_RAPID_COMMIT, &[])?,
                        _ => return Err(unknown(FIELD, token, GRAMMAR_DOC)),
                    }
                }
            }
        }
    }
    flush(&mut pending, &mut out)?;
    Ok(out)
}

/// Fill the next unset lifetime of an open IAADDR (preferred first).
fn fill_addr_lifetime(open: &mut OpenAddr, n: u32, token: &str) -> Result<(), EncodeError> {
    if open.preferred.is_none() {
        open.preferred = Some(n);
    } else if open.valid.is_none() {
        open.valid = Some(n);
    } else {
        return Err(unknown(FIELD, token, GRAMMAR_DOC));
    }
    Ok(())
}

/// Match one `name:args` token that opens a new top-level option (the
/// caller flushed any pending multi-value option first).
fn parse_named(
    out: &mut Vec<u8>,
    name: &str,
    args: &str,
    token: &str,
    pending: &mut Pending,
) -> Result<(), EncodeError> {
    match name {
        "client_id" => push_hex(out, OPT_CLIENT_ID, args),
        "server_id" => push_hex(out, OPT_SERVER_ID, args),
        "ia_na" => {
            // ia_na:IAID opens the pending IA_NA; t1/t2 and the
            // ia_addr lifetimes ride bare u32 continuations.
            let iaid: u32 = args
                .trim()
                .parse()
                .map_err(|_| bad(FIELD, format!("bad iaid in `{token}`")))?;
            *pending = Pending::Iana(PendingIana {
                iaid,
                t1: None,
                t2: None,
                subs: Vec::new(),
                open_addr: None,
            });
            Ok(())
        }
        "oro" => {
            let n: u16 = args
                .trim()
                .parse()
                .map_err(|_| bad(FIELD, format!("bad option code in `{token}`")))?;
            *pending = Pending::Codes { list: vec![n] };
            Ok(())
        }
        "dns" => {
            let ip: Ipv6Addr = args
                .trim()
                .parse()
                .map_err(|_| bad(FIELD, format!("bad address in `{token}`")))?;
            *pending = Pending::Dns { ips: vec![ip] };
            Ok(())
        }
        "domain" => {
            let wire = encode_domain_name(args.trim())?;
            push_tlv(out, OPT_DOMAIN_LIST, &wire)
        }
        "elapsed" => {
            let n: u16 = args
                .trim()
                .parse()
                .map_err(|_| bad(FIELD, format!("bad number in `{token}`")))?;
            push_tlv(out, OPT_ELAPSED_TIME, &n.to_be_bytes())
        }
        "hex" => {
            // hex:CODE:HEX — the raw escape hatch.
            let (code_s, hexpart) = args
                .split_once(':')
                .ok_or_else(|| bad(FIELD, format!("hex needs CODE:HEX in `{token}`")))?;
            let code: u16 = code_s
                .trim()
                .parse()
                .map_err(|_| bad(FIELD, format!("bad option code in `{token}`")))?;
            push_hex(out, code, hexpart)
        }
        _ => Err(unknown(FIELD, token, GRAMMAR_DOC)),
    }
}

fn flush(pending: &mut Pending, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    match std::mem::replace(pending, Pending::None) {
        Pending::None => Ok(()),
        Pending::Codes { list } => {
            let data: Vec<u8> = list.iter().flat_map(|n| n.to_be_bytes()).collect();
            push_tlv(out, OPT_ORO, &data)
        }
        Pending::Dns { ips } => {
            let data: Vec<u8> = ips.iter().flat_map(|ip| ip.octets()).collect();
            push_tlv(out, OPT_DNS_SERVERS, &data)
        }
        Pending::Iana(mut iana) => {
            flush_open_addr(&mut iana)?;
            let mut data = Vec::with_capacity(12 + iana.subs.len());
            data.extend_from_slice(&iana.iaid.to_be_bytes());
            data.extend_from_slice(&iana.t1.unwrap_or(0).to_be_bytes());
            data.extend_from_slice(&iana.t2.unwrap_or(0).to_be_bytes());
            data.extend_from_slice(&iana.subs);
            push_tlv(out, OPT_IA_NA, &data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_type_parse_render() {
        assert_eq!(parse_msg_type("solicit"), Some(1));
        assert_eq!(parse_msg_type("Reply"), Some(7));
        assert_eq!(parse_msg_type("info_req"), Some(11));
        assert_eq!(parse_msg_type("relay_forward"), Some(12));
        assert_eq!(parse_msg_type("5"), Some(5));
        assert_eq!(parse_msg_type("0"), None);
        assert_eq!(parse_msg_type("14"), None);
        assert_eq!(parse_msg_type("bogus"), None);
        assert_eq!(render_msg_type(1), "solicit");
        assert_eq!(render_msg_type(7), "reply");
        assert_eq!(render_msg_type(12), "relay_forward");
        assert_eq!(render_msg_type(200), "200");
    }

    #[test]
    fn grammar_singles() {
        assert_eq!(
            parse_options("client_id:hex:000102030405").unwrap(),
            vec![0, 1, 0, 6, 0, 1, 2, 3, 4, 5]
        );
        assert_eq!(
            parse_options("server_id:000102030405").unwrap(),
            vec![0, 2, 0, 6, 0, 1, 2, 3, 4, 5]
        );
        assert_eq!(
            parse_options("elapsed:100").unwrap(),
            vec![0, 8, 0, 2, 0, 100]
        );
        assert_eq!(parse_options("rapid").unwrap(), vec![0, 14, 0, 0]);
        assert_eq!(
            parse_options("domain:wrex.example").unwrap(),
            vec![
                0, 24, 0, 14, 4, b'w', b'r', b'e', b'x', 7, b'e', b'x', b'a', b'm', b'p', b'l',
                b'e', 0
            ]
        );
        // raw escape (option codes decimal in the grammar)
        assert_eq!(
            parse_options("hex:40:0102").unwrap(),
            vec![0, 40, 0, 2, 1, 2]
        );
    }

    #[test]
    fn grammar_continuations() {
        // oro: bare numbers continue the list
        assert_eq!(
            parse_options("oro:23,24,39").unwrap(),
            vec![0, 6, 0, 6, 0, 23, 0, 24, 0, 39]
        );
        // dns: bare addresses continue the pending option
        let out = parse_options("dns:2001:db8::1,2001:db8::2").unwrap();
        let mut want = vec![0, 23, 0, 32];
        want.extend("2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        want.extend("2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(out, want);
        // pending flushes at the next `name:` token
        assert_eq!(
            parse_options("oro:23,rapid").unwrap(),
            vec![0, 6, 0, 2, 0, 23, 0, 14, 0, 0]
        );
    }

    #[test]
    fn grammar_ia_na_nests_ia_addr() {
        // ia_na:IAID[,t1,t2] + ia_addr continuations → IAADDR sub-TLVs
        // inside the IA_NA payload.
        let out = parse_options("ia_na:287454020,300,600,ia_addr:2001:db8::10,3600,7200,elapsed:5")
            .unwrap();
        // elapsed flushes the pending IA_NA first: [3][len=40]
        // [iaid4][t1=300][t2=600][iaaddr tlv 28]
        let mut want = Vec::new();
        want.extend_from_slice(&[0, 3, 0, 40]);
        want.extend_from_slice(&287454020u32.to_be_bytes());
        want.extend_from_slice(&300u32.to_be_bytes());
        want.extend_from_slice(&600u32.to_be_bytes());
        // IAADDR sub-TLV: code 5, len 24, addr + preferred + valid
        want.extend_from_slice(&[0, 5, 0, 24]);
        want.extend_from_slice(&"2001:db8::10".parse::<Ipv6Addr>().unwrap().octets());
        want.extend_from_slice(&3600u32.to_be_bytes());
        want.extend_from_slice(&7200u32.to_be_bytes());
        want.extend_from_slice(&[0, 8, 0, 2, 0, 5]);
        assert_eq!(out, want);
        // t1/t2 unset default to 0 (the RFC 8415 §21.4 fixed part)
        let out = parse_options("ia_na:1,ia_addr:2001:db8::1").unwrap();
        assert_eq!(&out[4..8], &1u32.to_be_bytes()[..]);
        assert_eq!(&out[8..12], &0u32.to_be_bytes()[..]);
        assert_eq!(&out[12..16], &0u32.to_be_bytes()[..]);
        // default lifetimes when no continuations follow the address
        let out = parse_options("ia_na:1,ia_addr:2001:db8::1,ia_addr:2001:db8::2,60,120").unwrap();
        // sub-TLVs start after the 4-byte TLV header + 12-byte fixed
        // part: [code(2)][len(2)][iaid(4)][t1(4)][t2(4)] then subs.
        let sub1 = &out[16..44]; // 4-byte sub header + 24-byte IAADDR
        assert_eq!(&sub1[20..24], &0u32.to_be_bytes()[..]); // preferred 0
        assert_eq!(&sub1[24..28], &0u32.to_be_bytes()[..]); // valid 0
        let sub2 = &out[44..72];
        assert_eq!(&sub2[20..24], &60u32.to_be_bytes()[..]);
        assert_eq!(&sub2[24..28], &120u32.to_be_bytes()[..]);
    }

    #[test]
    fn grammar_errors() {
        assert!(parse_options("bogus").is_err());
        assert!(parse_options("client_id:zz").is_err());
        assert!(parse_options("elapsed:xyz").is_err());
        assert!(parse_options("ia_addr:2001:db8::1").is_err()); // no pending ia_na
        assert!(parse_options("dns:notanip").is_err());
        assert!(parse_options("hex:zz:0102").is_err());
        assert!(parse_options("hex:0102").is_err());
        assert!(parse_options("23").is_err()); // continuation with no pending
        assert!(parse_options("domain:").is_err());
        assert!(parse_options("domain:bad..name").is_err());
    }

    #[test]
    fn domain_name_roundtrip() {
        let wire = encode_domain_name("wrex.example").unwrap();
        assert_eq!(decode_domain_names(&wire).as_deref(), Some("wrex.example"));
        // two names in one region
        let mut two = encode_domain_name("a.b").unwrap();
        two.extend_from_slice(&encode_domain_name("c.d").unwrap());
        assert_eq!(decode_domain_names(&two).as_deref(), Some("a.b,c.d"));
        // dangling/overrunning labels: None
        assert_eq!(decode_domain_names(&[3, b'a', b'b']), None);
        assert_eq!(decode_domain_names(&[9, b'a']), None);
    }
}
