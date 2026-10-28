//! DHCP options value grammar (write side; RFC 2132 TLVs).
//!
//! Comma list of `type:NAME|N`, `mask:IP`, `routers:IP[,IP…]`,
//! `dns:IP[,IP…]`, `host:NAME`, `domain:NAME`, `req_ip:IP`,
//! `lease:SECS`, `renew:SECS`, `rebind:SECS`, `server:IP`,
//! `param_req:N[,N…]`, `max_msg:N`, `client_id:HEX`, `pad`, or the raw
//! escape `hex:CODE:HEX`. Multi-value options (`routers`, `dns`,
//! `param_req`) share the top-level comma with the item separator, so
//! bare addresses/numbers continue the previous option (the ipv4/tcp
//! options-grammar architecture). The codec appends the `end` (255)
//! marker itself.

use std::net::Ipv4Addr;

use wrex_core::EncodeError;
use wrex_core::options::{bad, named, tokens, unknown};

// Option codes (RFC 2132).
pub const OPT_PAD: u8 = 0;
pub const OPT_SUBNET_MASK: u8 = 1;
pub const OPT_ROUTER: u8 = 3;
pub const OPT_DNS_SERVERS: u8 = 6;
pub const OPT_HOST_NAME: u8 = 12;
pub const OPT_DOMAIN_NAME: u8 = 15;
pub const OPT_REQUESTED_IP: u8 = 50;
pub const OPT_ADDRESS_TIME: u8 = 51;
pub const OPT_MSG_TYPE: u8 = 53;
pub const OPT_SERVER_ID: u8 = 54;
pub const OPT_PARAM_REQ: u8 = 55;
pub const OPT_MAX_MSG_SIZE: u8 = 57;
pub const OPT_RENEWAL_TIME: u8 = 58;
pub const OPT_REBINDING_TIME: u8 = 59;
pub const OPT_CLIENT_ID: u8 = 61;
pub const OPT_END: u8 = 255;

/// DHCP message types (option 53, RFC 2131 §3.1).
pub const MSG_TYPES: [(&str, u8); 8] = [
    ("discover", 1),
    ("offer", 2),
    ("request", 3),
    ("decline", 4),
    ("ack", 5),
    ("nak", 6),
    ("release", 7),
    ("inform", 8),
];

/// Parse a message-type name (`discover`) or number (`1`).
pub fn parse_msg_type(raw: &str) -> Option<u8> {
    let raw = raw.trim();
    for (name, n) in MSG_TYPES {
        if raw.eq_ignore_ascii_case(name) {
            return Some(n);
        }
    }
    let n: u8 = raw.parse().ok()?;
    (1..=8).contains(&n).then_some(n)
}

/// Canonical lowercase name for a message type (numbers outside 1..=8
/// render as their decimal form).
pub fn render_msg_type(v: u8) -> String {
    for (name, n) in MSG_TYPES {
        if v == n {
            return name.to_string();
        }
    }
    v.to_string()
}

/// Does the raw options region carry a message-type (53) TLV? Used to
/// reject `dhcp.msg_type` + `type:` double-setting (a usage guard; the
/// walk stops at `end`/overrun, so a malformed region just answers
/// conservatively).
pub const fn scan_msg_type(region: &[u8]) -> bool {
    let mut cursor = 0usize;
    while cursor + 2 <= region.len() {
        let code = region[cursor];
        if code == OPT_PAD {
            cursor += 1;
            continue;
        }
        if code == OPT_END {
            return false;
        }
        let olen = region[cursor + 1] as usize;
        if cursor + 2 + olen > region.len() {
            return false;
        }
        if code == OPT_MSG_TYPE {
            return true;
        }
        cursor += 2 + olen;
    }
    false
}

enum Pending {
    None,
    /// Multi-address options (routers, dns servers).
    Addrs {
        code: u8,
        ips: Vec<Ipv4Addr>,
    },
    /// Parameter-request list (option codes).
    Codes {
        list: Vec<u8>,
    },
}

const FIELD: &str = "dhcp.options";
const KNOWN: &[&str] = &[
    "type",
    "mask",
    "routers",
    "dns",
    "host",
    "domain",
    "req_ip",
    "lease",
    "renew",
    "rebind",
    "server",
    "param_req",
    "max_msg",
    "client_id",
    "hex",
];

fn push_tlv(out: &mut Vec<u8>, code: u8, data: &[u8]) -> Result<(), EncodeError> {
    wrex_core::options::push_tlv_u8(FIELD, out, code, data)
}

fn push_ip(out: &mut Vec<u8>, code: u8, args: &str, token: &str) -> Result<(), EncodeError> {
    let ip: Ipv4Addr = args
        .trim()
        .parse()
        .map_err(|_| bad(FIELD, format!("bad address in `{token}`")))?;
    push_tlv(out, code, &ip.octets())
}

fn push_u32(out: &mut Vec<u8>, code: u8, args: &str, token: &str) -> Result<(), EncodeError> {
    let n: u32 = args
        .trim()
        .parse()
        .map_err(|_| bad(FIELD, format!("bad number in `{token}`")))?;
    push_tlv(out, code, &n.to_be_bytes())
}

fn push_u16(out: &mut Vec<u8>, code: u8, args: &str, token: &str) -> Result<(), EncodeError> {
    let n: u16 = args
        .trim()
        .parse()
        .map_err(|_| bad(FIELD, format!("bad number in `{token}`")))?;
    push_tlv(out, code, &n.to_be_bytes())
}

fn push_text(out: &mut Vec<u8>, code: u8, args: &str) -> Result<(), EncodeError> {
    push_tlv(out, code, args.as_bytes())
}

fn push_hex(out: &mut Vec<u8>, code: u8, args: &str) -> Result<(), EncodeError> {
    let hexpart = args.strip_prefix("hex:").unwrap_or(args);
    let bytes = wrex_core::value::parse_hex_bytes(hexpart.trim())
        .map_err(|e| bad(FIELD, format!("bad hex: {e}")))?;
    push_tlv(out, code, &bytes)
}

const GRAMMAR_DOC: &str = "valid: type:N, mask:IP, routers:IP…, dns:IP…, host:NAME, domain:NAME, \
req_ip:IP, lease:SECS, renew:SECS, rebind:SECS, server:IP, param_req:N…, max_msg:N, \
client_id:HEX, pad, hex:CODE:HEX";

/// Parse the options grammar into raw TLV bytes (without the `end`
/// marker — the codec appends it).
pub(crate) fn parse_options(raw: &str) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    let mut pending = Pending::None;
    for token in tokens(raw) {
        if let Some((name, args)) = named(token, KNOWN) {
            flush(&mut pending, &mut out)?;
            match name {
                "type" => {
                    let n = parse_msg_type(args)
                        .ok_or_else(|| bad(FIELD, format!("bad message type in `{token}`")))?;
                    push_tlv(&mut out, OPT_MSG_TYPE, &[n])?;
                }
                "mask" => push_ip(&mut out, OPT_SUBNET_MASK, args, token)?,
                "routers" => {
                    let ip: Ipv4Addr = args
                        .trim()
                        .parse()
                        .map_err(|_| bad(FIELD, format!("bad address in `{token}`")))?;
                    pending = Pending::Addrs {
                        code: OPT_ROUTER,
                        ips: vec![ip],
                    };
                }
                "dns" => {
                    let ip: Ipv4Addr = args
                        .trim()
                        .parse()
                        .map_err(|_| bad(FIELD, format!("bad address in `{token}`")))?;
                    pending = Pending::Addrs {
                        code: OPT_DNS_SERVERS,
                        ips: vec![ip],
                    };
                }
                "host" => push_text(&mut out, OPT_HOST_NAME, args)?,
                "domain" => push_text(&mut out, OPT_DOMAIN_NAME, args)?,
                "req_ip" => push_ip(&mut out, OPT_REQUESTED_IP, args, token)?,
                "lease" => push_u32(&mut out, OPT_ADDRESS_TIME, args, token)?,
                "renew" => push_u32(&mut out, OPT_RENEWAL_TIME, args, token)?,
                "rebind" => push_u32(&mut out, OPT_REBINDING_TIME, args, token)?,
                "server" => push_ip(&mut out, OPT_SERVER_ID, args, token)?,
                "param_req" => {
                    let n: u8 = args
                        .trim()
                        .parse()
                        .map_err(|_| bad(FIELD, format!("bad parameter code in `{token}`")))?;
                    pending = Pending::Codes { list: vec![n] };
                }
                "max_msg" => push_u16(&mut out, OPT_MAX_MSG_SIZE, args, token)?,
                "client_id" => push_hex(&mut out, OPT_CLIENT_ID, args)?,
                "hex" => {
                    // hex:CODE:HEX — the raw escape hatch.
                    let (code_s, hexpart) = args
                        .split_once(':')
                        .ok_or_else(|| bad(FIELD, format!("hex needs CODE:HEX in `{token}`")))?;
                    let code: u8 = code_s
                        .trim()
                        .parse()
                        .map_err(|_| bad(FIELD, format!("bad option code in `{token}`")))?;
                    push_hex(&mut out, code, hexpart)?;
                }
                _ => return Err(unknown(FIELD, token, GRAMMAR_DOC)),
            }
        } else {
            // Continuation tokens: bare addresses extend routers/dns,
            // bare numbers extend a parameter-request list.
            match (&mut pending, token.parse::<Ipv4Addr>()) {
                (Pending::Addrs { ips, .. }, Ok(ip)) => ips.push(ip),
                (Pending::Codes { list }, _) if token.parse::<u8>().is_ok() => {
                    list.push(token.parse::<u8>().unwrap())
                }
                _ => {
                    flush(&mut pending, &mut out)?;
                    match token {
                        "pad" => out.push(OPT_PAD),
                        _ => return Err(unknown(FIELD, token, GRAMMAR_DOC)),
                    }
                }
            }
        }
    }
    flush(&mut pending, &mut out)?;
    Ok(out)
}

fn flush(pending: &mut Pending, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    match std::mem::replace(pending, Pending::None) {
        Pending::None => Ok(()),
        Pending::Addrs { code, ips } => {
            let mut data = Vec::with_capacity(ips.len() * 4);
            for ip in &ips {
                data.extend_from_slice(&ip.octets());
            }
            push_tlv(out, code, &data)
        }
        Pending::Codes { list } => push_tlv(out, OPT_PARAM_REQ, &list),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_type_parse_render() {
        assert_eq!(parse_msg_type("discover"), Some(1));
        assert_eq!(parse_msg_type("Inform"), Some(8));
        assert_eq!(parse_msg_type("5"), Some(5));
        assert_eq!(parse_msg_type("0"), None);
        assert_eq!(parse_msg_type("9"), None);
        assert_eq!(parse_msg_type("bogus"), None);
        assert_eq!(render_msg_type(1), "discover");
        assert_eq!(render_msg_type(6), "nak");
        assert_eq!(render_msg_type(200), "200");
    }

    #[test]
    fn grammar_singles() {
        assert_eq!(parse_options("type:discover").unwrap(), vec![53, 1, 1]);
        assert_eq!(
            parse_options("mask:255.255.255.0").unwrap(),
            vec![1, 4, 255, 255, 255, 0]
        );
        assert_eq!(
            parse_options("server:10.0.0.1").unwrap(),
            vec![54, 4, 10, 0, 0, 1]
        );
        assert_eq!(
            parse_options("lease:3600").unwrap(),
            vec![51, 4, 0, 0, 14, 16]
        );
        assert_eq!(parse_options("max_msg:1500").unwrap(), vec![57, 2, 5, 220]);
        assert_eq!(
            parse_options("host:wrex").unwrap(),
            vec![12, 4, b'w', b'r', b'e', b'x']
        );
        assert_eq!(
            parse_options("client_id:hex:010203040506").unwrap(),
            vec![61, 6, 1, 2, 3, 4, 5, 6]
        );
        assert_eq!(parse_options("client_id:0102").unwrap(), vec![61, 2, 1, 2]);
        // raw escape (option codes are decimal in the grammar)
        assert_eq!(
            parse_options("hex:82:0105dc").unwrap(),
            vec![82, 3, 1, 5, 0xdc]
        );
        assert_eq!(parse_options("pad,pad").unwrap(), vec![0, 0]);
    }

    #[test]
    fn grammar_continuations() {
        // routers/dns: bare addresses continue the pending option
        assert_eq!(
            parse_options("routers:10.0.0.1,10.0.0.2").unwrap(),
            vec![3, 8, 10, 0, 0, 1, 10, 0, 0, 2]
        );
        assert_eq!(
            parse_options("dns:10.0.0.53").unwrap(),
            vec![6, 4, 10, 0, 0, 53]
        );
        // param_req: bare numbers continue the list
        assert_eq!(
            parse_options("param_req:1,3,6,15").unwrap(),
            vec![55, 4, 1, 3, 6, 15]
        );
        // mixed list: pending flushes at the next `name:` token
        assert_eq!(
            parse_options("routers:10.0.0.1,lease:60").unwrap(),
            vec![3, 4, 10, 0, 0, 1, 51, 4, 0, 0, 0, 60]
        );
        assert_eq!(parse_options("param_req:1,pad").unwrap(), vec![55, 1, 1, 0]);
    }

    #[test]
    fn grammar_errors() {
        assert!(parse_options("bogus").is_err());
        assert!(parse_options("mask:notanip").is_err());
        assert!(parse_options("lease:xyz").is_err());
        assert!(parse_options("type:9").is_err());
        assert!(parse_options("hex:zz:0102").is_err());
        assert!(parse_options("hex:0102").is_err());
        assert!(parse_options("10.0.0.1").is_err()); // continuation with no pending
        assert!(parse_options("42").is_err()); // continuation with no pending
    }

    #[test]
    fn scan_msg_type_tlv_walk() {
        assert!(scan_msg_type(&[53, 1, 1]));
        assert!(scan_msg_type(&[0, 0, 53, 1, 5]));
        assert!(!scan_msg_type(&[51, 4, 0, 0, 14, 16, 255, 53, 1, 1]));
        assert!(!scan_msg_type(&[]));
        assert!(!scan_msg_type(&[53])); // truncated TLV
        assert!(scan_msg_type(&[53, 1, 1, 255]));
        assert!(!scan_msg_type(&[61, 2, 1, 2, 255]));
        // overrun data: conservative false
        assert!(!scan_msg_type(&[61, 9, 1, 2]));
    }
}
