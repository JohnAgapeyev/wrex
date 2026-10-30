//! TCP options value grammar (write side).
//!
//! Comma list of `eol`, `nop`, `mss:1460`, `ws:7`, `sackok`,
//! `sack:L,R,…` (relative sequence numbers), or `hex:…` raw escape.
//! The whole options region is zero-padded to a 4-byte multiple by the
//! caller. Tokenization, the known-name split and the error mapping
//! ride the shared [`wrex_core::options`] skeleton (HP3-d); the value
//! encoders and the pending-sack continuation stay here.

use wrex_core::EncodeError;
use wrex_core::options::{bad, named, tokens, unknown};

pub(crate) const OPT_EOL: u8 = 0;
pub(crate) const OPT_NOP: u8 = 1;
pub(crate) const OPT_MSS: u8 = 2;
pub(crate) const OPT_WS: u8 = 3;
pub(crate) const OPT_SACKOK: u8 = 4;
pub(crate) const OPT_SACK: u8 = 5;
pub(crate) const OPT_TS: u8 = 8;
const OPT_MPTCP: u8 = 30;
const OPT_TFO: u8 = 34;

/// Tranche 22a: the kind vocabulary shared by the write grammar, the
/// settable `opt.N.kind` record path and the read-side renderer —
/// name ↔ code, RFC 9293 §3.1 plus the common extensions (MPTCP
/// RFC 8684 §3, TFO RFC 7413).
const KIND_TABLE: &[(&str, u8)] = &[
    ("eol", OPT_EOL),
    ("nop", OPT_NOP),
    ("mss", OPT_MSS),
    ("ws", OPT_WS),
    ("sackok", OPT_SACKOK),
    ("sack", OPT_SACK),
    ("ts", OPT_TS),
    ("mptcp", OPT_MPTCP),
    ("tfo", OPT_TFO),
];

/// Parse one `opt.N.kind` value: a table name or a bare number
/// (`"14"` — the unknown-kind spelling, `hex:` covers the data).
pub(crate) fn parse_kind(raw: &str) -> Option<u8> {
    for (name, code) in KIND_TABLE {
        if wrex_core::str_eq(name, raw) {
            return Some(*code);
        }
    }
    raw.parse().ok().filter(|&c: &u8| c != 0 && c != 1)
}

/// Render one option kind code: its table name, or the bare number
/// for kinds outside the vocabulary (the dissect-side twin of the
/// `parse_kind` numeric spelling).
pub(crate) fn render_kind(code: u8) -> std::borrow::Cow<'static, str> {
    for (name, k) in KIND_TABLE {
        if *k == code {
            return std::borrow::Cow::Borrowed(name);
        }
    }
    std::borrow::Cow::Owned(code.to_string())
}

const FIELD: &str = "tcp.options";
const KNOWN: &[&str] = &["mss", "ws", "sack", "hex"];
const GRAMMAR_DOC: &str = "eol, nop, mss:1460, ws:7, sackok, sack:L,R,…, hex:…";

/// Parse the options grammar into raw option bytes. `sack` values share the
/// top-level comma, so bare integers continue the pending sack option.
pub(crate) fn parse_options(raw: &str) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    let mut pending_sack: Option<Vec<u32>> = None;
    for token in tokens(raw) {
        if let Some((name, args)) = named(token, KNOWN) {
            flush_sack(&mut pending_sack, &mut out)?;
            match name {
                "eol" => out.push(OPT_EOL),
                "nop" => out.push(OPT_NOP),
                "mss" => {
                    let mss: u16 = args
                        .trim()
                        .parse()
                        .map_err(|_| bad(FIELD, format!("mss needs a value in `{token}`")))?;
                    out.extend_from_slice(&[OPT_MSS, 4, (mss >> 8) as u8, mss as u8]);
                }
                "ws" => {
                    let ws: u8 = args
                        .trim()
                        .parse()
                        .map_err(|_| bad(FIELD, format!("ws needs a value in `{token}`")))?;
                    out.extend_from_slice(&[OPT_WS, 3, ws, OPT_NOP]); // padded with nop
                }
                "sackok" => out.extend_from_slice(&[OPT_SACKOK, 2, OPT_NOP, OPT_NOP]),
                "sack" => {
                    let nums: Vec<u32> = match args {
                        a if a.trim().is_empty() => Vec::new(),
                        a => a
                            .split(',')
                            .map(|s| s.trim().parse::<u32>())
                            .collect::<Result<_, _>>()
                            .map_err(|_| bad(FIELD, format!("sack needs L,R,… in `{token}`")))?,
                    };
                    pending_sack = Some(nums);
                }
                "hex" => {
                    let bytes = wrex_core::value::parse_hex_bytes(args.trim())
                        .map_err(|e| bad(FIELD, format!("bad hex: {e}")))?;
                    out.extend_from_slice(&bytes);
                }
                _ => unreachable!("the KNOWN list is the dispatch table"),
            }
        } else {
            // Bare token: the colon-less known options are list items
            // too (the old split treated them as named; the gated split
            // sends them here), bare integers continue a pending sack,
            // anything else is the unknown option.
            match token {
                "eol" => {
                    flush_sack(&mut pending_sack, &mut out)?;
                    out.push(OPT_EOL);
                }
                "nop" => {
                    flush_sack(&mut pending_sack, &mut out)?;
                    out.push(OPT_NOP);
                }
                "sackok" => {
                    flush_sack(&mut pending_sack, &mut out)?;
                    out.extend_from_slice(&[OPT_SACKOK, 2, OPT_NOP, OPT_NOP]);
                }
                _ => match token.parse::<u32>() {
                    Ok(n) => match &mut pending_sack {
                        Some(nums) => nums.push(n),
                        None => return Err(unknown(FIELD, token, GRAMMAR_DOC)),
                    },
                    Err(_) => return Err(unknown(FIELD, token, GRAMMAR_DOC)),
                },
            }
        }
    }
    flush_sack(&mut pending_sack, &mut out)?;
    Ok(out)
}

fn flush_sack(pending: &mut Option<Vec<u32>>, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    if let Some(nums) = pending.take() {
        if nums.is_empty() {
            return Err(bad(FIELD, "sack needs at least one value"));
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
    wrex_core::options::pad_to_grid(len, 4)
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

    /// Tranche 22a: the name↔code table round-trips (parse_kind /
    /// render_code symmetry); unknown kinds parse and render bare
    /// numbers; eol/nop never parse numerically (their wire spelling
    /// IS the kind byte).
    #[test]
    fn kind_table_symmetry() {
        for (name, code) in KIND_TABLE {
            assert_eq!(parse_kind(name), Some(*code), "{name}");
            assert_eq!(&render_kind(*code), name, "{code}");
        }
        assert_eq!(parse_kind("14"), Some(14));
        assert_eq!(&render_kind(14), "14");
        assert_eq!(parse_kind("0"), None, "eol is name-only");
        assert_eq!(parse_kind("1"), None, "nop is name-only");
        assert_eq!(parse_kind("bogus"), None);
        assert_eq!(parse_kind(""), None);
    }
}
