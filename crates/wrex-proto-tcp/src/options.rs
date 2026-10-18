//! TCP options value grammar (write side).
//!
//! Comma list of `eol`, `nop`, `mss:1460`, `ws:7`, `sackok`,
//! `sack:L,R,…` (relative sequence numbers), or `hex:…` raw escape.
//! The whole options region is zero-padded to a 4-byte multiple by the
//! caller.

use wrex_core::EncodeError;

const OPT_EOL: u8 = 0;
const OPT_NOP: u8 = 1;
const OPT_MSS: u8 = 2;
const OPT_WS: u8 = 3;
const OPT_SACKOK: u8 = 4;
const OPT_SACK: u8 = 5;

fn bad(detail: String) -> EncodeError {
    EncodeError::IncompatibleStack { detail }
}

/// Parse the options grammar into raw option bytes. `sack` values share the
/// top-level comma, so bare integers continue the pending sack option.
pub(crate) fn parse_options(raw: &str) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    let mut pending_sack: Option<Vec<u32>> = None;
    for token in raw.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }
        if let Some(hex) = token.strip_prefix("hex:") {
            flush_sack(&mut pending_sack, &mut out)?;
            let bytes = wrex_core::value::parse_hex_bytes(hex.trim())
                .map_err(|e| bad(format!("tcp.options: bad hex: {e}")))?;
            out.extend_from_slice(&bytes);
            continue;
        }
        let (name, args) = match token.split_once(':') {
            Some((n, a)) => (n, Some(a)),
            None => (token, None),
        };
        match name {
            "eol" => {
                flush_sack(&mut pending_sack, &mut out)?;
                out.push(OPT_EOL);
            }
            "nop" => {
                flush_sack(&mut pending_sack, &mut out)?;
                out.push(OPT_NOP);
            }
            "mss" => {
                flush_sack(&mut pending_sack, &mut out)?;
                let mss: u16 = args
                    .unwrap_or("")
                    .trim()
                    .parse()
                    .map_err(|_| bad(format!("tcp.options: mss needs a value in `{token}`")))?;
                out.extend_from_slice(&[OPT_MSS, 4, (mss >> 8) as u8, mss as u8]);
            }
            "ws" => {
                flush_sack(&mut pending_sack, &mut out)?;
                let ws: u8 = args
                    .unwrap_or("")
                    .trim()
                    .parse()
                    .map_err(|_| bad(format!("tcp.options: ws needs a value in `{token}`")))?;
                out.extend_from_slice(&[OPT_WS, 3, ws, OPT_NOP]); // padded with nop
            }
            "sackok" => {
                flush_sack(&mut pending_sack, &mut out)?;
                out.extend_from_slice(&[OPT_SACKOK, 2, OPT_NOP, OPT_NOP]);
            }
            "sack" => {
                flush_sack(&mut pending_sack, &mut out)?;
                let nums: Vec<u32> = match args {
                    Some(a) if !a.trim().is_empty() => a
                        .split(',')
                        .map(|s| s.trim().parse::<u32>())
                        .collect::<Result<_, _>>()
                        .map_err(|_| bad(format!("tcp.options: sack needs L,R,… in `{token}`")))?,
                    _ => Vec::new(),
                };
                pending_sack = Some(nums);
            }
            _ => {
                // Bare token: continue a pending sack, else unknown option.
                if let Ok(n) = token.parse::<u32>() {
                    match &mut pending_sack {
                        Some(nums) => nums.push(n),
                        None => {
                            return Err(bad(format!(
                                "tcp.options: unknown option `{token}` (valid: eol, nop, mss:1460, ws:7, sackok, sack:L,R,…, hex:…)"
                            )));
                        }
                    }
                } else {
                    return Err(bad(format!(
                        "tcp.options: unknown option `{token}` (valid: eol, nop, mss:1460, ws:7, sackok, sack:L,R,…, hex:…)"
                    )));
                }
            }
        }
    }
    flush_sack(&mut pending_sack, &mut out)?;
    Ok(out)
}

fn flush_sack(pending: &mut Option<Vec<u32>>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    if let Some(nums) = pending.take() {
        if nums.is_empty() {
            return Err(bad("tcp.options: sack needs at least one value".into()));
        }
        out.push(OPT_SACK);
        out.push(2 + 4 * nums.len() as u8);
        for n in &nums {
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
    Ok(())
}

/// Zero-pad to a 4-byte multiple (options region alignment).
pub(crate) fn pad_len(len: usize) -> usize {
    (4 - len % 4) % 4
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grammar() {
        assert_eq!(parse_options("eol").unwrap(), vec![0]);
        assert_eq!(parse_options("nop").unwrap(), vec![1]);
        assert_eq!(parse_options("mss:1460").unwrap(), vec![2, 4, 0x05, 0xb4]);
        assert_eq!(parse_options("ws:7").unwrap(), vec![3, 3, 7, 1]);
        assert_eq!(parse_options("sackok").unwrap(), vec![4, 2, 1, 1]);
        let sack = parse_options("sack:1,2").unwrap();
        assert_eq!(sack, vec![5, 10, 0, 0, 0, 1, 0, 0, 0, 2]);
        let mixed = parse_options("nop,mss:1460,hex:00").unwrap();
        assert_eq!(mixed, vec![1, 2, 4, 0x05, 0xb4, 0]);
        assert!(parse_options("bogus").is_err());
        assert!(parse_options("mss:abc").is_err());
        assert!(parse_options("sack:x").is_err());
    }

    #[test]
    fn padding() {
        assert_eq!(pad_len(0), 0);
        assert_eq!(pad_len(3), 1);
        assert_eq!(pad_len(4), 0);
    }
}
