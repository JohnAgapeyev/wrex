//! IPv4 options value grammar (write side).
//!
//! Comma list of `eol`, `nop`, `rr:IP[,IP…]`, `ssrr:IP[,IP…]`,
//! `lsrr:IP[,IP…]`, `ts:FLAG,CNT`, or `hex:…` raw escape. Route and
//! timestamp arguments share the top-level comma, so bare IPv4 addresses
//! continue the previous route option and bare integers continue a
//! `ts` option. The whole options region is zero-padded to a 4-byte
//! multiple by the caller.

use std::net::Ipv4Addr;

use wrex_core::EncodeError;

const OPT_EOL: u8 = 0;
const OPT_NOP: u8 = 1;
const OPT_RR: u8 = 7;
const OPT_TS: u8 = 68;
const OPT_LSRR: u8 = 131;
const OPT_SSRR: u8 = 137;

enum Pending {
    None,
    Route { kind: u8, ips: Vec<Ipv4Addr> },
    Ts { flag: u8, cnt: Option<usize> },
}

fn bad(detail: String) -> EncodeError {
    EncodeError::IncompatibleStack { detail }
}

/// Parse the options grammar into raw option bytes.
pub(crate) fn parse_options(raw: &str) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    let mut pending = Pending::None;
    for token in raw.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        if let Some((name, args)) = token.split_once(':') {
            flush(&mut pending, &mut out)?;
            match name {
                "eol" => out.push(OPT_EOL),
                "nop" => out.push(OPT_NOP),
                "rr" | "ssrr" | "lsrr" => {
                    let kind = match name {
                        "rr" => OPT_RR,
                        "ssrr" => OPT_SSRR,
                        _ => OPT_LSRR,
                    };
                    let ips: Vec<Ipv4Addr> = match args {
                        a if a.trim().is_empty() => Vec::new(),
                        a => a
                            .split(',')
                            .map(|s| s.trim().parse::<Ipv4Addr>())
                            .collect::<Result<_, _>>()
                            .map_err(|_| {
                                bad(format!("ipv4.options: bad route address in `{token}`"))
                            })?,
                    };
                    pending = Pending::Route { kind, ips };
                }
                "ts" => {
                    let flag: u8 = args.trim().parse().map_err(|_| {
                        bad(format!("ipv4.options: ts needs FLAG,CNT in `{token}`"))
                    })?;
                    pending = Pending::Ts { flag, cnt: None };
                }
                "hex" => {
                    let bytes = wrex_core::value::parse_hex_bytes(args.trim())
                        .map_err(|e| bad(format!("ipv4.options: bad hex: {e}")))?;
                    out.extend_from_slice(&bytes);
                }
                _ => {
                    return Err(bad(format!(
                        "ipv4.options: unknown option `{token}` (valid: eol, nop, rr:IP…, ssrr:IP…, lsrr:IP…, ts:FLAG,CNT, hex:…)"
                    )));
                }
            }
        } else {
            // Continuation tokens: bare addresses extend a route option,
            // bare integers complete `ts:FLAG,CNT`.
            match (&mut pending, token.parse::<Ipv4Addr>()) {
                (Pending::Route { ips, .. }, Ok(ip)) => ips.push(ip),
                (Pending::Ts { cnt, .. }, _) if token.parse::<usize>().is_ok() => {
                    *cnt = Some(token.parse::<usize>().unwrap());
                }
                (_, Ok(_)) | (_, Err(_)) => {
                    // Bare eol/nop tokens are also valid list items.
                    match token {
                        "eol" => {
                            flush(&mut pending, &mut out)?;
                            out.push(OPT_EOL)
                        }
                        "nop" => {
                            flush(&mut pending, &mut out)?;
                            out.push(OPT_NOP)
                        }
                        _ => {
                            return Err(bad(format!(
                                "ipv4.options: unknown option `{token}` (valid: eol, nop, rr:IP…, ssrr:IP…, lsrr:IP…, ts:FLAG,CNT, hex:…)"
                            )));
                        }
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
        Pending::Route { kind, ips } => {
            if ips.is_empty() {
                return Err(bad(
                    "ipv4.options: route option needs at least one address".into()
                ));
            }
            out.push(kind);
            out.push(3 + 4 * ips.len() as u8);
            out.push(4); // pointer
            for ip in &ips {
                out.extend_from_slice(&ip.octets());
            }
            Ok(())
        }
        Pending::Ts { flag, cnt } => {
            let cnt = cnt.ok_or_else(|| {
                bad("ipv4.options: ts needs FLAG,CNT (comma shares the item separator)".into())
            })?;
            out.push(OPT_TS);
            out.push(4 + 4 * cnt as u8);
            out.push(5); // pointer
            out.push(flag);
            out.extend(std::iter::repeat_n(0u8, 4 * cnt));
            Ok(())
        }
    }
}

/// Zero-pad to a 4-byte multiple (options region alignment).
pub(crate) const fn pad_len(len: usize) -> usize {
    (4 - len % 4) % 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grammar() {
        assert_eq!(parse_options("eol").unwrap(), vec![0]);
        assert_eq!(parse_options("nop").unwrap(), vec![1]);
        assert_eq!(parse_options("nop,nop,eol").unwrap(), vec![1, 1, 0]);
        // multi-IP route via comma continuation
        let rr = parse_options("rr:10.0.0.1,10.0.0.2").unwrap();
        assert_eq!(rr, vec![7, 3 + 8, 4, 10, 0, 0, 1, 10, 0, 0, 2]);
        let lsrr = parse_options("lsrr:1.2.3.4").unwrap();
        assert_eq!(lsrr, vec![131, 7, 4, 1, 2, 3, 4]);
        let ssrr = parse_options("ssrr:1.2.3.4").unwrap();
        assert_eq!(ssrr, vec![137, 7, 4, 1, 2, 3, 4]);
        // ts: FLAG then CNT via continuation
        let ts = parse_options("ts:0,2").unwrap();
        assert_eq!(ts, vec![68, 4 + 8, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let hex = parse_options("hex:0104090a").unwrap();
        assert_eq!(hex, vec![0x01, 0x04, 0x09, 0x0a]);
        // mixed
        let mixed = parse_options("nop,rr:1.1.1.1,hex:00").unwrap();
        assert_eq!(mixed, vec![1, 7, 7, 4, 1, 1, 1, 1, 0]);
        assert!(parse_options("bogus").is_err());
        assert!(parse_options("rr:notanip").is_err());
        assert!(parse_options("ts:x,2").is_err());
        assert!(parse_options("ts:0").is_err()); // missing CNT
        assert!(parse_options("rr:1.2.3.4,notanip").is_err());
    }

    #[test]
    fn padding() {
        assert_eq!(pad_len(0), 0);
        assert_eq!(pad_len(1), 3);
        assert_eq!(pad_len(4), 0);
        assert_eq!(pad_len(7), 1);
    }
}
