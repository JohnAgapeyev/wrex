//! The options-grammar skeleton (HP3-d, the rule of three applied):
//! the tokenization, known-name splitting, raw-TLV pushing and pointed
//! error mapping shared by the five codec list grammars (`ip`, `tcp`,
//! `dhcp`, `dhcp6`, `icmpv6` — ~1,674 lines total before the
//! extraction). Value encoders and pending-continuation semantics stay
//! codec-side (the honest boundary: dhcp6's nested IAADDR and icmpv6's
//! prefix plastering push on any deeper abstraction and cost more than
//! the duplication saves).
//!
//! Every helper takes the codec's field label (`"dhcp.options"`) so
//! errors stay pointed at the grammar that raised them.

use crate::error::EncodeError;

/// The comma-list token stream: split, trim, empty items skipped.
/// One token = one grammar item or continuation.
pub fn tokens(raw: &str) -> impl Iterator<Item = &str> {
    raw.split(',').map(str::trim).filter(|t| !t.is_empty())
}

/// Split a **known** `name:args` token — the uniform gotcha fix.
///
/// A bare continuation token may itself contain `:` (an IPv6 address:
/// `prefix:64,2001:db8::1,…`), so the split only fires when the head
/// is one of the codec's known option names; everything else feeds the
/// open option as a continuation. The two codecs whose continuations
/// never contain `:` (`ip`: IPv4/numbers, `tcp`: numbers) were safe
/// only by accident of their value types — the shared rule is uniform
/// and reads the same everywhere now.
pub fn named<'a>(token: &'a str, known: &[&str]) -> Option<(&'a str, &'a str)> {
    let (name, args) = token.split_once(':')?;
    known.contains(&name).then_some((name, args))
}

/// The pointed grammar error for `<field>` (e.g. `"dhcp.options"`).
pub fn bad(field: &str, msg: impl AsRef<str>) -> EncodeError {
    EncodeError::IncompatibleStack {
        detail: format!("{field}: {}", msg.as_ref()),
    }
}

/// The unknown-option error carrying the grammar's vocabulary.
pub fn unknown(field: &str, token: &str, valid: &str) -> EncodeError {
    bad(field, format!("unknown option `{token}` (valid: {valid})"))
}

/// Append one u8-code/u8-len TLV (the dhcp/RFC 2132 shape). The
/// 255-byte cap is the pointed error, never a silent truncation.
pub fn push_tlv_u8(
    field: &str,
    out: &mut Vec<u8>,
    code: u8,
    data: &[u8],
) -> Result<(), EncodeError> {
    if data.len() > u8::MAX as usize {
        return Err(bad(
            field,
            format!("option {code} exceeds {} bytes", u8::MAX),
        ));
    }
    out.push(code);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
    Ok(())
}

/// Append one u16-code/u16-len TLV (the dhcp6/RFC 8415 shape).
pub fn push_tlv_u16(
    field: &str,
    out: &mut Vec<u8>,
    code: u16,
    data: &[u8],
) -> Result<(), EncodeError> {
    if data.len() > u16::MAX as usize {
        return Err(bad(
            field,
            format!("option {code} exceeds {} bytes", u16::MAX),
        ));
    }
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

/// Zero-pad to an N-byte grid: how many padding bytes a region of
/// `len` needs (`ip`/`tcp` options: 4; the icmpv6/dhcp6 TLV regions:
/// 8).
pub const fn pad_to_grid(len: usize, grid: usize) -> usize {
    (grid - len % grid) % grid
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN: &[&str] = &["alpha", "beta"];

    #[test]
    fn tokens_split_trim_skip() {
        let all: Vec<&str> = tokens("a, b ,,c,").collect();
        assert_eq!(all, vec!["a", "b", "c"]);
        assert_eq!(tokens("").count(), 0);
        assert_eq!(tokens(" , ,").count(), 0);
    }

    #[test]
    fn named_known_only() {
        assert_eq!(named("alpha:1", KNOWN), Some(("alpha", "1")));
        assert_eq!(named("beta:", KNOWN), Some(("beta", "")));
        assert_eq!(named("alpha", KNOWN), None, "no colon: continuation");
        assert_eq!(
            named("2001:db8::1", KNOWN),
            None,
            "colons in a continuation do not make it a named option"
        );
        assert_eq!(
            named("gamma:1", KNOWN),
            None,
            "unknown heads fall to the continuation branch (the codec's own error)"
        );
        assert_eq!(named("", KNOWN), None);
    }

    #[test]
    fn error_mapping_is_pointed() {
        let e = bad("dhcp.options", "boom");
        assert!(
            matches!(e, EncodeError::IncompatibleStack { ref detail } if detail.contains("dhcp.options: boom"))
        );
        let u = unknown("tcp.options", "mystery", "eol, nop");
        assert!(matches!(u, EncodeError::IncompatibleStack { ref detail }
            if detail.contains("tcp.options: unknown option `mystery` (valid: eol, nop)")));
    }

    #[test]
    fn tlv_push_shapes() {
        let mut out = Vec::new();
        push_tlv_u8("f", &mut out, 53, &[1]).unwrap();
        assert_eq!(out, vec![53, 1, 1]);
        push_tlv_u16("f", &mut out, 23, &[0x20, 0x01]).unwrap();
        assert_eq!(out, vec![53, 1, 1, 0, 23, 0, 2, 0x20, 0x01]);
        // The caps are pointed errors.
        let big = vec![0u8; 256];
        assert!(push_tlv_u8("f", &mut out, 1, &big).is_err());
        let big16 = vec![0u8; u16::MAX as usize + 1];
        assert!(push_tlv_u16("f", &mut out, 1, &big16).is_err());
    }

    #[test]
    fn grid_padding() {
        assert_eq!(pad_to_grid(0, 4), 0);
        assert_eq!(pad_to_grid(1, 4), 3);
        assert_eq!(pad_to_grid(4, 4), 0);
        assert_eq!(pad_to_grid(7, 4), 1);
        assert_eq!(pad_to_grid(0, 8), 0);
        assert_eq!(pad_to_grid(10, 8), 6);
        assert_eq!(pad_to_grid(8, 8), 0);
    }
}
