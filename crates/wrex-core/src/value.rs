use std::sync::LazyLock;

use bytes::Bytes;

use crate::error::SpecError;
use crate::schema::{FieldKind, FieldSchema};

/// A typed field value in a [`crate::spec::LayerSpec`] or a dissected layer.
///
/// `Bytes` is cheap-to-clone (`bytes::Bytes`), so `Value` is `Clone` throughout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Bool(bool),
    Int(u128),
    Bytes(Bytes),
    Str(String),
    Ipv4(std::net::Ipv4Addr),
    Mac([u8; 6]),
    List(Vec<Value>),
}

/// Canonical MAC rendering `aa:bb:cc:dd:ee:ff` (lowercase hex).
pub fn mac_string(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

impl serde::Serialize for Value {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        match self {
            Value::Bool(b) => serializer.serialize_bool(*b),
            Value::Int(n) => serializer.serialize_u128(*n),
            Value::Bytes(b) => serializer.serialize_str(&hex::encode(b)),
            Value::Str(s) => serializer.serialize_str(s),
            Value::Ipv4(a) => serializer.serialize_str(&a.to_string()),
            Value::Mac(m) => serializer.serialize_str(&mac_string(*m)),
            Value::List(items) => {
                let mut seq = serializer.serialize_seq(Some(items.len()))?;
                for item in items {
                    seq.serialize_element(item)?;
                }
                seq.end()
            }
        }
    }
}

impl Value {
    /// The zero/default value for a field kind, independent of any schema default.
    pub fn zero_for(kind: FieldKind) -> Value {
        match kind {
            FieldKind::U8
            | FieldKind::U16
            | FieldKind::U32
            | FieldKind::U64
            | FieldKind::U128
            | FieldKind::FlagSet => Value::Int(0),
            FieldKind::Bytes | FieldKind::ByteList => Value::Bytes(Bytes::new()),
            FieldKind::Str => Value::Str(String::new()),
            FieldKind::Ipv4 => Value::Ipv4(std::net::Ipv4Addr::UNSPECIFIED),
            FieldKind::Mac => Value::Mac([0; 6]),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Value::Bool(_) => "bool",
            Value::Int(_) => "int",
            Value::Bytes(_) => "bytes",
            Value::Str(_) => "str",
            Value::Ipv4(_) => "ipv4",
            Value::Mac(_) => "mac",
            Value::List(_) => "list",
        }
    }
}

/// Parse `raw` against a field schema using the pinned value grammar.
///
/// Grammar: ints in decimal/`0x`/`0b`/`0o` (range-checked against the field
/// width); IPv4 dotted quad; MAC `aa:bb:cc:dd:ee:ff` (or `-` separated);
/// `Bytes`/`ByteList` as `hex:…`, `text:…`, `@<path>`, `@-` (stdin, read once
/// per invocation, cached), `repeat:<N>x<hex>`; `FlagSet` as bit names
/// (`,`/`+` separated) or a raw integer; `Bool` as `true|false|1|0`; `Str` raw
/// or `text:`-prefixed. `List` accumulates only via repeated CLI flags — no
/// inline list syntax.
pub fn parse_value(field: &FieldSchema, raw: &str) -> Result<Value, SpecError> {
    let bad = |reason: String| {
        Err(SpecError::BadValue {
            path: field.name.to_string(),
            raw: raw.to_string(),
            reason,
        })
    };
    match field.kind {
        FieldKind::U8 | FieldKind::U16 | FieldKind::U32 | FieldKind::U64 | FieldKind::U128 => {
            let n = parse_int(raw).map_err(|reason| SpecError::BadValue {
                path: field.name.to_string(),
                raw: raw.to_string(),
                reason,
            })?;
            let max = field.kind.int_max().unwrap();
            if n > max {
                bad(format!("value out of range for {}", field.kind.type_name()))
            } else {
                Ok(Value::Int(n))
            }
        }
        FieldKind::FlagSet => {
            // Raw integer form (decimal / 0x… / 0b… / 0o…) when it parses,
            // bit names (`syn,ack` / `syn+ack`) otherwise.
            if let Ok(n) = parse_int(raw) {
                return if n > u8::MAX as u128 {
                    bad("flag set must fit in 8 bits".to_string())
                } else {
                    Ok(Value::Int(n))
                };
            }
            let mut mask: u128 = 0;
            for name in raw.split([',', '+']) {
                let name = name.trim();
                if name.is_empty() {
                    continue;
                }
                match field.bit_pos(name) {
                    Some(bit) => mask |= 1 << bit,
                    None => {
                        return bad(format!(
                            "unknown flag `{name}` (valid: {})",
                            field.bit_names.join(", ")
                        ));
                    }
                }
            }
            Ok(Value::Int(mask))
        }
        FieldKind::Ipv4 => {
            let a: std::net::Ipv4Addr = raw.trim().parse().map_err(|_| SpecError::BadValue {
                path: field.name.to_string(),
                raw: raw.to_string(),
                reason: "expected dotted-quad IPv4 (a.b.c.d)".to_string(),
            })?;
            Ok(Value::Ipv4(a))
        }
        FieldKind::Mac => {
            let sep = if raw.contains(':') { ':' } else { '-' };
            let parts: Vec<&str> = raw.split(sep).collect();
            let invalid = || SpecError::BadValue {
                path: field.name.to_string(),
                raw: raw.to_string(),
                reason: "expected MAC aa:bb:cc:dd:ee:ff (':' or '-')".to_string(),
            };
            if parts.len() != 6 {
                return Err(invalid());
            }
            let mut mac = [0u8; 6];
            for (i, part) in parts.iter().enumerate() {
                if part.is_empty() || part.len() > 2 || !part.chars().all(|c| c.is_ascii_hexdigit())
                {
                    return Err(invalid());
                }
                mac[i] = u8::from_str_radix(part, 16).map_err(|_| invalid())?;
            }
            Ok(Value::Mac(mac))
        }
        FieldKind::Bytes | FieldKind::ByteList => parse_bytes_value(field, raw),
        FieldKind::Str => Ok(Value::Str(
            raw.strip_prefix("text:").unwrap_or(raw).to_string(),
        )),
    }
}

pub(crate) fn parse_int(raw: &str) -> Result<u128, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("empty integer".to_string());
    }
    let (radix, digits) = if let Some(d) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X"))
    {
        (16, d)
    } else if let Some(d) = raw.strip_prefix("0b").or_else(|| raw.strip_prefix("0B")) {
        (2, d)
    } else if let Some(d) = raw.strip_prefix("0o").or_else(|| raw.strip_prefix("0O")) {
        (8, d)
    } else {
        (10, raw)
    };
    let digits = digits.replace('_', "");
    if digits.is_empty() {
        return Err("empty integer".to_string());
    }
    u128::from_str_radix(&digits, radix).map_err(|_| format!("not a valid base-{radix} integer"))
}

/// Parse the boolean grammar (`true|false|1|0`, case-insensitive) used by
/// flag-bit subpaths (`tcp.flags.syn=true`).
pub fn parse_bool(raw: &str) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(format!("expected true|false|1|0, got `{raw}`")),
    }
}

pub fn parse_hex_bytes(raw: &str) -> Result<Vec<u8>, String> {
    if !raw.len().is_multiple_of(2) {
        return Err("hex string must have even length".to_string());
    }
    let bytes = hex::decode(raw).map_err(|e| format!("invalid hex: {e}"))?;
    Ok(bytes)
}

fn parse_bytes_value(field: &FieldSchema, raw: &str) -> Result<Value, SpecError> {
    let bad = |reason: &str| SpecError::BadValue {
        path: field.name.to_string(),
        raw: raw.to_string(),
        reason: reason.to_string(),
    };
    if let Some(rest) = raw.strip_prefix("hex:") {
        let v = parse_hex_bytes(rest).map_err(|e| bad(&e))?;
        Ok(Value::Bytes(Bytes::from(v)))
    } else if let Some(rest) = raw.strip_prefix("text:") {
        Ok(Value::Bytes(Bytes::from(rest.as_bytes().to_vec())))
    } else if raw == "@-" {
        Ok(Value::Bytes(stdin_bytes()))
    } else if let Some(path) = raw.strip_prefix('@') {
        std::fs::read(path)
            .map_err(|e| bad(&format!("cannot read `{path}`: {e}")))
            .map(|v| Value::Bytes(Bytes::from(v)))
    } else if let Some(rest) = raw.strip_prefix("repeat:") {
        let (count_s, hex_part) = rest
            .split_once('x')
            .ok_or_else(|| bad("expected repeat:<N>x<hex>"))?;
        let count: usize = count_s
            .trim()
            .parse()
            .map_err(|_| bad("bad repeat count"))?;
        let unit = parse_hex_bytes(hex_part.trim()).map_err(|e| bad(&e))?;
        if unit.is_empty() {
            return Err(bad("repeat unit must be non-empty hex"));
        }
        if count.checked_mul(unit.len()).map(|n| n <= (1 << 32)) != Some(true) {
            return Err(bad("repeat expansion too large"));
        }
        let mut out = Vec::with_capacity(count * unit.len());
        for _ in 0..count {
            out.extend_from_slice(&unit);
        }
        Ok(Value::Bytes(Bytes::from(out)))
    } else {
        Err(bad(
            "expected hex:…, text:…, @<path>, @-, or repeat:<N>x<hex>",
        ))
    }
}

static STDIN: std::sync::LazyLock<Bytes> =
    LazyLock::new(|| read_stdin_from(std::io::stdin().lock()));

/// Stdin bytes, read once per invocation and cached (`@-` value grammar).
pub fn stdin_bytes() -> Bytes {
    STDIN.clone()
}

pub(crate) fn read_stdin_from(mut r: impl std::io::Read) -> Bytes {
    let mut buf = Vec::new();
    // Ignore read errors: an empty value is the least-surprising result for a
    // closed/broken stdin, and craft will report the packet it can build.
    let _ = r.read_to_end(&mut buf);
    Bytes::from(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{FieldKind, FieldSchema};

    fn field(name: &'static str, kind: FieldKind) -> FieldSchema {
        FieldSchema {
            name,
            kind,
            bit_names: &[],
            default: Value::zero_for(kind),
            required: false,
            doc: "",
        }
    }

    fn flag_field(name: &'static str, bits: &'static [&'static str]) -> FieldSchema {
        FieldSchema {
            name,
            kind: FieldKind::FlagSet,
            bit_names: bits,
            default: Value::zero_for(FieldKind::FlagSet),
            required: false,
            doc: "",
        }
    }

    fn bytes_field(name: &'static str) -> FieldSchema {
        field(name, FieldKind::Bytes)
    }

    #[test]
    fn int_grammar_branches() {
        let f = field("ttl", FieldKind::U8);
        assert_eq!(parse_value(&f, "63").unwrap(), Value::Int(63));
        assert_eq!(parse_value(&f, "0x7f").unwrap(), Value::Int(0x7f));
        assert_eq!(parse_value(&f, "0b0111_1111").unwrap(), Value::Int(127));
        assert_eq!(parse_value(&f, "0o17").unwrap(), Value::Int(15));
        // widths
        for (kind, max) in [
            (FieldKind::U8, 255u128),
            (FieldKind::U16, 65535),
            (FieldKind::U32, u32::MAX as u128),
            (FieldKind::U64, u64::MAX as u128),
            (FieldKind::U128, u128::MAX),
        ] {
            let f = field("w", kind);
            // 2^128 as a decimal literal: `u128::MAX + 1` would overflow.
            let over = match max.checked_add(1) {
                Some(m) => m.to_string(),
                None => "340282366920938463463374607431768211456".to_string(),
            };
            assert!(parse_value(&f, &over).is_err(), "{kind:?} overflow");
            assert_eq!(parse_value(&f, &max.to_string()).unwrap(), Value::Int(max));
        }
        assert!(parse_value(&f, "300").is_err()); // u8 range
        assert!(parse_value(&f, "").is_err());
        assert!(parse_value(&f, "12x").is_err());
        let e = parse_value(&f, "300").unwrap_err();
        assert!(matches!(e, SpecError::BadValue { .. }));
        assert!(e.to_string().contains("out of range"));
    }

    #[test]
    fn ipv4_and_mac_grammar() {
        let fi = field("src", FieldKind::Ipv4);
        assert_eq!(
            parse_value(&fi, "127.0.0.1").unwrap(),
            Value::Ipv4("127.0.0.1".parse().unwrap())
        );
        assert!(parse_value(&fi, "127.1").is_err());
        assert!(parse_value(&fi, "256.0.0.1").is_err());
        let fm = field("dst", FieldKind::Mac);
        assert_eq!(
            parse_value(&fm, "aa:bb:cc:dd:ee:ff").unwrap(),
            Value::Mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(
            parse_value(&fm, "AA-BB-CC-DD-EE-FF").unwrap(),
            Value::Mac([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert!(parse_value(&fm, "aa:bb:cc:dd:ee").is_err()); // 5 groups
        assert!(parse_value(&fm, "aa:bb:cc:dd:ee:gg").is_err());
        assert!(parse_value(&fm, "aabbccddeeff").is_err());
    }

    #[test]
    fn bytes_grammar_branches() {
        let f = bytes_field("payload");
        assert_eq!(
            parse_value(&f, "hex:deadbeef").unwrap(),
            Value::Bytes(Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]))
        );
        assert_eq!(
            parse_value(&f, "hex:DEADbeef").unwrap(),
            Value::Bytes(Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]))
        );
        assert!(parse_value(&f, "hex:abc").is_err()); // odd length
        assert!(parse_value(&f, "hex:xyz").is_err());
        assert_eq!(
            parse_value(&f, "text:hello").unwrap(),
            Value::Bytes(Bytes::from_static(b"hello"))
        );
        assert_eq!(
            parse_value(&f, "repeat:3x00ff").unwrap(),
            Value::Bytes(Bytes::from_static(&[0x00, 0xff, 0x00, 0xff, 0x00, 0xff]))
        );
        assert!(parse_value(&f, "repeat:Ax00ff").is_err());
        assert!(parse_value(&f, "repeat:4x").is_err());
        // file bytes
        let dir = std::env::temp_dir().join("wrex-core-value-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("payload.bin");
        std::fs::write(&path, [0x01, 0x02, 0x03]).unwrap();
        let raw = format!("@{}", path.display());
        assert_eq!(
            parse_value(&f, &raw).unwrap(),
            Value::Bytes(Bytes::from_static(&[0x01, 0x02, 0x03]))
        );
        assert!(parse_value(&f, "@/nonexistent/wrex/zz").is_err());
        // stdin
        let bytes = read_stdin_from(&b"raw stdin bytes"[..]);
        assert_eq!(bytes.as_ref(), b"raw stdin bytes");
        // bare value without prefix is a spec error
        assert!(parse_value(&f, "deadbeef").is_err());
    }

    #[test]
    fn flagset_grammar() {
        let bits: &[&'static str] = &["cwr", "ece", "urg", "ack", "psh", "rst", "syn", "fin"];
        let f = flag_field("flags", bits);
        // indices: cwr=0 ece=1 urg=2 ack=3 psh=4 rst=5 syn=6 fin=7
        assert_eq!(parse_value(&f, "syn").unwrap(), Value::Int(0x02)); // syn = bit 1
        assert_eq!(parse_value(&f, "syn,ack").unwrap(), Value::Int(0x12)); // syn|ack = 0x02|0x10
        assert_eq!(parse_value(&f, "syn+ack").unwrap(), Value::Int(0x12));
        assert_eq!(parse_value(&f, "ack,syn").unwrap(), Value::Int(0x12));
        assert_eq!(parse_value(&f, "0x02").unwrap(), Value::Int(2));
        assert_eq!(parse_value(&f, "2").unwrap(), Value::Int(2));
        assert!(parse_value(&f, "SYN").is_err()); // case-sensitive bit names
        let e = parse_value(&f, "syn,xxx").unwrap_err();
        assert!(e.to_string().contains("unknown flag `xxx`"));
        assert!(
            e.to_string()
                .contains("valid: cwr, ece, urg, ack, psh, rst, syn, fin")
        );
        assert!(parse_value(&f, "0x1ff").is_err()); // > 8 bits
        // empty mask from only separators is fine (nothing set)
        assert_eq!(parse_value(&f, ",").unwrap(), Value::Int(0));
    }

    #[test]
    fn bool_and_str_grammar() {
        for (raw, want) in [("true", true), ("1", true), ("false", false), ("0", false)] {
            assert_eq!(parse_bool(raw).unwrap(), want);
        }
        assert!(parse_bool("yes").is_err());
        assert!(parse_bool("TRUE").is_ok()); // case-insensitive
        let fs = field("name", FieldKind::Str);
        assert_eq!(parse_value(&fs, "eth0").unwrap(), Value::Str("eth0".into()));
        assert_eq!(
            parse_value(&fs, "text:eth0").unwrap(),
            Value::Str("eth0".into())
        );
    }

    #[test]
    fn value_helpers() {
        assert_eq!(Value::zero_for(FieldKind::U16), Value::Int(0));
        assert_eq!(
            Value::zero_for(FieldKind::Bytes),
            Value::Bytes(Bytes::new())
        );
        assert_eq!(Value::Bool(true).kind(), "bool");
        assert_eq!(Value::Mac([0; 6]).kind(), "mac");
    }
}
