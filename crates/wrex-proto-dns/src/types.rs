//! DNS type/class name tables (the Str-typed field grammar, both
//! directions) with RFC 3597 `TYPE<n>`/`CLASS<n>` and bare-numeric
//! fallbacks on parse.

/// Record type numbers (RFC 1035 + the tranche-3 set; the T20a-2 table
/// completion: the full typed-rdata alias set, rendering names first).
pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_HINFO: u16 = 13;
pub const TYPE_MX: u16 = 15;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_NAPTR: u16 = 35;
pub const TYPE_DNAME: u16 = 39;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_DS: u16 = 43;
pub const TYPE_SSHFP: u16 = 44;
pub const TYPE_RRSIG: u16 = 46;
pub const TYPE_NSEC: u16 = 47;
pub const TYPE_DNSKEY: u16 = 48;
pub const TYPE_TLSA: u16 = 52;
pub const TYPE_SVCB: u16 = 64;
pub const TYPE_HTTPS: u16 = 65;
pub const TYPE_CAA: u16 = 257;
pub const TYPE_ANY: u16 = 255;

/// Class numbers.
pub const CLASS_IN: u16 = 1;
pub const CLASS_CH: u16 = 3;
pub const CLASS_HS: u16 = 4;
pub const CLASS_ANY: u16 = 255;

/// Known type names (rendering order = the table).
const TYPES: &[(u16, &str)] = &[
    (TYPE_A, "A"),
    (TYPE_NS, "NS"),
    (TYPE_CNAME, "CNAME"),
    (TYPE_SOA, "SOA"),
    (TYPE_PTR, "PTR"),
    (TYPE_HINFO, "HINFO"),
    (TYPE_MX, "MX"),
    (TYPE_TXT, "TXT"),
    (TYPE_AAAA, "AAAA"),
    (TYPE_SRV, "SRV"),
    (TYPE_NAPTR, "NAPTR"),
    (TYPE_DNAME, "DNAME"),
    (TYPE_OPT, "OPT"),
    (TYPE_DS, "DS"),
    (TYPE_SSHFP, "SSHFP"),
    (TYPE_RRSIG, "RRSIG"),
    (TYPE_NSEC, "NSEC"),
    (TYPE_DNSKEY, "DNSKEY"),
    (TYPE_TLSA, "TLSA"),
    (TYPE_SVCB, "SVCB"),
    (TYPE_HTTPS, "HTTPS"),
    (TYPE_CAA, "CAA"),
    (TYPE_ANY, "ANY"),
];

const CLASSES: &[(u16, &str)] = &[
    (CLASS_IN, "IN"),
    (CLASS_CH, "CH"),
    (CLASS_HS, "HS"),
    (CLASS_ANY, "ANY"),
];

/// Render a type number: known name, else RFC 3597 `TYPE<n>`.
pub fn render_type(num: u16) -> String {
    TYPES
        .iter()
        .find(|(n, _)| *n == num)
        .map(|(_, name)| (*name).to_string())
        .unwrap_or_else(|| format!("TYPE{num}"))
}

/// Render a class number: known name, else RFC 3597 `CLASS<n>`.
pub fn render_class(num: u16) -> String {
    CLASSES
        .iter()
        .find(|(n, _)| *n == num)
        .map(|(_, name)| (*name).to_string())
        .unwrap_or_else(|| format!("CLASS{num}"))
}

/// Parse a type: known name (case-insensitive), `TYPE<n>`/`TYPE0x<hex>`
/// (RFC 3597) or a bare decimal.
pub fn parse_type(raw: &str) -> Option<u16> {
    parse_table(TYPES, "TYPE", raw)
}

/// Parse a class: known name, `CLASS<n>` or a bare decimal.
pub fn parse_class(raw: &str) -> Option<u16> {
    parse_table(CLASSES, "CLASS", raw)
}

fn parse_table(table: &[(u16, &str)], generic_prefix: &str, raw: &str) -> Option<u16> {
    let raw = raw.trim();
    if let Some((num, _)) = table
        .iter()
        .find(|(_, name)| name.eq_ignore_ascii_case(raw))
    {
        return Some(*num);
    }
    let upper = raw.to_ascii_uppercase();
    let digits = match upper.strip_prefix(generic_prefix) {
        Some(d) => d,
        // Bare decimal fallback (dig-style `query example.com 15`).
        None => return raw.parse::<u16>().ok(),
    };
    if let Some(hex) = digits.strip_prefix("0X") {
        return u16::from_str_radix(hex, 16).ok();
    }
    digits.parse::<u16>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_known_names() {
        for &(num, name) in TYPES {
            assert_eq!(render_type(num), name);
            assert_eq!(parse_type(name), Some(num));
            assert_eq!(parse_type(&name.to_ascii_lowercase()), Some(num));
        }
        for &(num, name) in CLASSES {
            assert_eq!(render_class(num), name);
            assert_eq!(parse_class(name), Some(num));
        }
    }

    #[test]
    fn rfc3597_and_numeric() {
        assert_eq!(parse_type("TYPE123"), Some(123));
        assert_eq!(parse_type("TYPE0x7b"), Some(123));
        assert_eq!(parse_type("123"), Some(123));
        assert_eq!(parse_class("CLASS99"), Some(99));
        assert_eq!(parse_class("99"), Some(99));
        assert_eq!(render_type(123), "TYPE123");
        assert_eq!(render_class(99), "CLASS99");
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_type("BOGUS"), None);
        assert_eq!(parse_type("TYPE99999"), None);
        assert_eq!(parse_type("TYPE"), None);
        assert_eq!(parse_type(""), None);
        assert_eq!(parse_type("-1"), None);
        assert_eq!(parse_class("INX"), None);
    }
}
