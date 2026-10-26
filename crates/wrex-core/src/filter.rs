//! `--filter` engine: space-separated AND-terms, `path<op>value`.
//!
//! Validated against the registry schema upfront (typo → `FilterError` at
//! startup). Paths absent from a dissected packet evaluate false.

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use crate::codec::Registry;
use crate::dissect::DissectedPacket;
use crate::error::FilterError;
use crate::schema::{FieldKind, FieldSchema, ResolvedField};
use crate::value::{Value, parse_bool, parse_int};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl Op {
    /// Operator spelling, in scan order (two-char forms first).
    const SPELINGS: [&'static str; 6] = ["!=", "<=", ">=", "=", "<", ">"];

    /// (const: `str` matching is not const-callable — byte-pattern form.)
    const fn parse(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.len() == 1 {
            return match b[0] {
                b'=' => Some(Self::Eq),
                b'<' => Some(Self::Lt),
                b'>' => Some(Self::Gt),
                _ => None,
            };
        }
        if b.len() == 2 {
            return match [b[0], b[1]] {
                [b'!', b'='] => Some(Self::Ne),
                [b'<', b'='] => Some(Self::Le),
                [b'>', b'='] => Some(Self::Ge),
                _ => None,
            };
        }
        None
    }
    const fn spelling(self) -> &'static str {
        match self {
            Op::Eq => "=",
            Op::Ne => "!=",
            Op::Lt => "<",
            Op::Le => "<=",
            Op::Gt => ">",
            Op::Ge => ">=",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum TermValue {
    Int(u128),
    /// IPv4 with optional CIDR prefix (membership on `=`/`!=`).
    Ipv4 {
        addr: Ipv4Addr,
        prefix: Option<u8>,
    },
    /// IPv6 with optional CIDR prefix (membership on `=`/`!=`).
    Ipv6 {
        addr: Ipv6Addr,
        prefix: Option<u8>,
    },
    Mac([u8; 6]),
    /// Hex prefix match.
    HexPrefix(Bytes),
    /// Bit names, all of which must be set (flagset `=`).
    Names(Vec<String>),
    /// Per-bit flag subpath (`tcp.flags.syn=true`).
    FlagBit {
        name: String,
        set: bool,
    },
    Str(String),
}

#[derive(Clone, Debug)]
struct Term {
    layer: &'static str,
    /// Aggregate field name (`flags.syn` → `flags`).
    field: String,
    op: Op,
    value: TermValue,
}

/// A parsed filter expression (conjunction of terms).
#[derive(Clone, Debug, Default)]
pub struct Filter {
    terms: Vec<Term>,
}

impl Filter {
    /// Parse and validate against the registry schema.
    pub fn parse(registry: &Registry, expr: &str) -> Result<Self, FilterError> {
        let mut terms = Vec::new();
        for raw in expr.split_whitespace() {
            if raw.is_empty() {
                continue;
            }
            terms.push(parse_term(registry, raw)?);
        }
        Ok(Self { terms })
    }

    pub fn is_empty(&self) -> bool {
        self.terms.is_empty()
    }

    /// All terms must match (AND). Absent paths are false.
    pub fn matches(&self, packet: &DissectedPacket) -> bool {
        self.terms.iter().all(|t| matches_term(packet, t))
    }
}

fn parse_term(registry: &Registry, raw: &str) -> Result<Term, FilterError> {
    let bad = |reason: String| FilterError::BadTerm {
        term: raw.to_string(),
        reason,
    };
    // Earliest operator occurrence wins; two-char spellings are scanned
    // before their one-char prefixes so "<=" never half-matches as "<".
    let mut found: Option<(usize, Op)> = None;
    for spelling in Op::SPELINGS {
        if let Some(pos) = raw.find(spelling)
            && found.is_none_or(|(p, _)| pos < p)
        {
            found = Some((pos, Op::parse(spelling).unwrap()));
        }
    }
    let (pos, op) = found.ok_or_else(|| bad("expected <path><op><value>".into()))?;
    let (path, value_raw) = raw.split_at(pos);
    let value_raw = &value_raw[op.spelling().len()..];
    let path = path.trim();
    let value_raw = value_raw.trim();
    if path.is_empty() {
        return Err(bad("empty path".into()));
    }
    if value_raw.is_empty() {
        return Err(bad("empty value".into()));
    }
    let (layer_name, field_path) = path
        .split_once('.')
        .ok_or_else(|| bad("expected <layer>.<field> path".into()))?;
    let schema = registry
        .get(layer_name)
        .ok_or_else(|| bad(format!("unknown layer `{layer_name}`")))?
        .schema();
    let resolved = schema
        .resolve(field_path)
        .ok_or_else(|| bad(format!("unknown field `{layer_name}.{field_path}`")))?;

    let value = match resolved {
        ResolvedField::Field(field) => term_value_for(field, op, value_raw, &bad)?,
        ResolvedField::RecordField { field, .. } => term_value_for(field, op, value_raw, &bad)?,
        ResolvedField::FlagBit { .. } => {
            if matches!(op, Op::Eq | Op::Ne) {
                let set = parse_bool(value_raw).map_err(bad)?;
                // `flags.syn` → bit name `syn`
                let name = field_path.split_once('.').map_or("", |(_, tail)| tail);
                TermValue::FlagBit {
                    name: name.to_string(),
                    set,
                }
            } else {
                return Err(bad("flag bits support only = and != in filters".into()));
            }
        }
    };

    // Lookup key in the dissected layer: the full path for record fields
    // (dissect emits `an.0.type` keys directly), the aggregate name
    // otherwise (`flags.syn` merges into `flags`).
    let field = match &resolved {
        ResolvedField::RecordField {
            record,
            index,
            field,
        } => format!("{}.{}.{}", record.name, index, field.name),
        _ => field_path
            .split_once('.')
            .map_or_else(|| field_path.to_string(), |(head, _)| head.to_string()),
    };

    Ok(Term {
        layer: schema.kind,
        field: field.to_string(),
        op,
        value,
    })
}

/// Kind-driven value grammar shared by flat fields and record fields.
fn term_value_for(
    field: &FieldSchema,
    op: Op,
    value_raw: &str,
    bad: &dyn Fn(String) -> FilterError,
) -> Result<TermValue, FilterError> {
    let bad = |reason: String| bad(reason);
    Ok(match field.kind {
        FieldKind::U8 | FieldKind::U16 | FieldKind::U32 | FieldKind::U64 | FieldKind::U128 => {
            TermValue::Int(parse_int(value_raw).map_err(bad)?)
        }
        FieldKind::FlagSet => {
            if op == Op::Eq {
                // Bit names (all set) or raw integer.
                if let Ok(n) = parse_int(value_raw) {
                    TermValue::Int(n)
                } else {
                    let names: Vec<String> = value_raw
                        .split([',', '+'])
                        .map(str::trim)
                        .map(str::to_string)
                        .collect();
                    if names.iter().any(|n| field.bit_pos(n).is_none()) {
                        return Err(bad(format!(
                            "unknown flag(s) in `{value_raw}` (valid: {})",
                            field.bit_names.join(", ")
                        )));
                    }
                    TermValue::Names(names)
                }
            } else {
                TermValue::Int(parse_int(value_raw).map_err(bad)?)
            }
        }
        FieldKind::Ipv4 => {
            if matches!(op, Op::Eq | Op::Ne) {
                let (addr, prefix) = parse_ipv4_cidr(value_raw).map_err(bad)?;
                TermValue::Ipv4 { addr, prefix }
            } else {
                return Err(bad("ipv4 fields support only = and != in filters".into()));
            }
        }
        FieldKind::Ipv6 => {
            if matches!(op, Op::Eq | Op::Ne) {
                let (addr, prefix) = parse_ipv6_cidr(value_raw).map_err(bad)?;
                TermValue::Ipv6 { addr, prefix }
            } else {
                return Err(bad("ipv6 fields support only = and != in filters".into()));
            }
        }
        FieldKind::Mac => {
            if matches!(op, Op::Eq | Op::Ne) {
                TermValue::Mac(parse_mac(value_raw).map_err(bad)?)
            } else {
                return Err(bad("mac fields support only = and != in filters".into()));
            }
        }
        FieldKind::Bytes | FieldKind::ByteList => {
            if matches!(op, Op::Eq | Op::Ne) {
                let hex = value_raw.strip_prefix("hex:").unwrap_or(value_raw);
                let bytes = crate::value::parse_hex_bytes(hex).map_err(bad)?;
                TermValue::HexPrefix(Bytes::from(bytes))
            } else {
                return Err(bad("bytes fields support only = and != in filters".into()));
            }
        }
        FieldKind::Str => TermValue::Str(value_raw.to_string()),
    })
}

fn parse_ipv4_cidr(raw: &str) -> Result<(Ipv4Addr, Option<u8>), String> {
    match raw.split_once('/') {
        Some((addr, prefix)) => {
            let addr: Ipv4Addr = addr.trim().parse().map_err(|_| "bad IPv4".to_string())?;
            let prefix: u8 = prefix
                .trim()
                .parse()
                .map_err(|_| "bad prefix".to_string())?;
            if prefix > 32 {
                return Err("prefix > 32".to_string());
            }
            Ok((addr, Some(prefix)))
        }
        None => {
            let addr: Ipv4Addr = raw.trim().parse().map_err(|_| "bad IPv4".to_string())?;
            Ok((addr, None))
        }
    }
}

fn parse_ipv6_cidr(raw: &str) -> Result<(Ipv6Addr, Option<u8>), String> {
    match raw.split_once('/') {
        Some((addr, prefix)) => {
            let addr: Ipv6Addr = addr.trim().parse().map_err(|_| "bad IPv6".to_string())?;
            let prefix: u8 = prefix
                .trim()
                .parse()
                .map_err(|_| "bad prefix".to_string())?;
            if prefix > 128 {
                return Err("prefix > 128".to_string());
            }
            Ok((addr, Some(prefix)))
        }
        None => {
            let addr: Ipv6Addr = raw.trim().parse().map_err(|_| "bad IPv6".to_string())?;
            Ok((addr, None))
        }
    }
}

fn parse_mac(raw: &str) -> Result<[u8; 6], String> {
    static MAC_FIELD: FieldSchema = FieldSchema {
        name: "mac",
        kind: FieldKind::Mac,
        bit_names: &[],
        default: Value::Mac([0; 6]),
        required: false,
        doc: "",
    };
    match crate::value::parse_value(&MAC_FIELD, raw) {
        Ok(Value::Mac(m)) => Ok(m),
        Ok(_) => Err("not a mac".to_string()),
        Err(e) => Err(e.to_string()),
    }
}

fn matches_term(packet: &DissectedPacket, t: &Term) -> bool {
    let Some(layer) = packet.layers.iter().find(|l| l.kind == t.layer) else {
        return false;
    };
    let Some(value) = layer.fields.get(&t.field) else {
        return false;
    };
    eval(value, t)
}

fn eval(value: &Value, t: &Term) -> bool {
    let eq = |hit: bool| if t.op == Op::Ne { !hit } else { hit };
    match (&t.value, value) {
        (TermValue::Int(want), Value::Int(v)) => match t.op {
            // Packet value (left) compared against the filter value.
            Op::Eq => *v == *want,
            Op::Ne => *v != *want,
            Op::Lt => *v < *want,
            Op::Le => *v <= *want,
            Op::Gt => *v > *want,
            Op::Ge => *v >= *want,
        },
        (TermValue::Ipv4 { addr, prefix }, Value::Ipv4(v)) => {
            if !matches!(t.op, Op::Eq | Op::Ne) {
                return false;
            }
            let hit = match prefix {
                Some(p) => {
                    let mask: u32 = if *p == 0 { 0 } else { u32::MAX << (32 - *p) };
                    (u32::from(*v) & mask) == (u32::from(*addr) & mask)
                }
                None => v == addr,
            };
            eq(hit)
        }
        (TermValue::Ipv6 { addr, prefix }, Value::Ipv6(v)) => {
            if !matches!(t.op, Op::Eq | Op::Ne) {
                return false;
            }
            let hit = match prefix {
                Some(p) => {
                    let bits = 128 - *p as u32;
                    let mask: u128 = if *p == 0 {
                        0
                    } else {
                        u128::MAX.checked_shl(bits).unwrap_or(0)
                    };
                    let vi = u128::from_be_bytes(v.octets());
                    let ai = u128::from_be_bytes(addr.octets());
                    (vi & mask) == (ai & mask)
                }
                None => v == addr,
            };
            eq(hit)
        }
        (TermValue::Mac(want), Value::Mac(v)) => eq(want == v),
        (TermValue::HexPrefix(prefix), Value::Bytes(b)) => {
            eq(b.len() >= prefix.len() && b[..prefix.len()] == prefix[..])
        }
        (TermValue::Names(want), Value::List(items)) => {
            let names: Vec<&str> = items
                .iter()
                .filter_map(|v| match v {
                    Value::Str(s) => Some(&**s),
                    _ => None,
                })
                .collect();
            eq(want.iter().all(|w| names.contains(&w.as_str())))
        }
        (TermValue::FlagBit { name, set }, Value::List(items)) => {
            let names: Vec<&str> = items
                .iter()
                .filter_map(|v| match v {
                    Value::Str(s) => Some(&**s),
                    _ => None,
                })
                .collect();
            eq(names.contains(&name.as_str()) == *set)
        }
        (TermValue::Str(want), Value::Str(v)) => {
            let (v, want) = (&**v, &**want);
            match t.op {
                Op::Eq => v == want,
                Op::Ne => v != want,
                Op::Lt => v < want,
                Op::Le => v <= want,
                Op::Gt => v > want,
                Op::Ge => v >= want,
            }
        }
        _ => false,
    }
}

#[cfg(kani)]
mod kani_proofs {
    //! Kani proofs for the filter engine's comparison core (the pass-2
    //! formal-coverage plan). String parsing (Filter::parse) is out of
    //! Kani scope — exponential over symbolic strings, the documented
    //! `decode_name` retirement class — carried by units + the
    //! `fuzz_filter` target instead. What's provable here: the `eval`
    //! core over symbolic scalar values and ops never panics and its
    //! operator semantics are exact (complements, antisymmetry), and
    //! the prefix-mask arithmetic the CIDR membership rides on.
    use super::*;

    /// A minimal in-layer term for direct eval() proofs.
    fn term(value: TermValue, op: Op) -> Term {
        Term {
            layer: "l",
            field: "f".to_string(),
            op,
            value,
        }
    }

    /// Int comparisons over fully symbolic (v, want) and every op:
    /// never a panic; Eq/Ne are complements; Le/Ge agree only on
    /// equality (antisymmetry — the trichotomy core).
    #[kani::proof]
    fn eval_int_ops_are_exact() {
        let v = kani::any::<u128>();
        let want = kani::any::<u128>();
        for op in [Op::Eq, Op::Ne, Op::Lt, Op::Le, Op::Gt, Op::Ge] {
            let t = term(TermValue::Int(want), op);
            let verdict = eval(&Value::Int(v), &t);
            match op {
                Op::Eq => assert_eq!(verdict, v == want),
                Op::Ne => assert_eq!(verdict, v != want),
                Op::Lt => assert_eq!(verdict, v < want),
                Op::Le => assert_eq!(verdict, v <= want),
                Op::Gt => assert_eq!(verdict, v > want),
                Op::Ge => assert_eq!(verdict, v >= want),
            }
        }
        // The complement pair: !(Eq) == Ne for any operands.
        let eq = eval(&Value::Int(v), &term(TermValue::Int(want), Op::Eq));
        let ne = eval(&Value::Int(v), &term(TermValue::Int(want), Op::Ne));
        assert_eq!(eq, !ne);
        // Antisymmetry: Le && Ge ⟺ equality.
        let le = eval(&Value::Int(v), &term(TermValue::Int(want), Op::Le));
        let ge = eval(&Value::Int(v), &term(TermValue::Int(want), Op::Ge));
        assert_eq!(le && ge, v == want);
    }

    /// The v4 CIDR mask arithmetic: for any prefix ≤ 32 (the parser's
    /// bound), membership is reflexive (an address in its own /p) and
    /// mask application never panics — the shift `32 - p` is
    /// underflow-free by construction.
    #[kani::proof]
    fn ipv4_cidr_mask_is_safe_and_reflexive() {
        let octets: [u8; 4] = kani::any();
        let addr = Ipv4Addr::from(octets);
        let p = kani::any::<u8>();
        kani::assume(p <= 32);
        for op in [Op::Eq, Op::Ne] {
            let t = term(
                TermValue::Ipv4 {
                    addr,
                    prefix: Some(p),
                },
                op,
            );
            // Reflexive: the address itself always matches its own
            // CIDR (the mask kills exactly the low bits).
            let verdict = eval(&Value::Ipv4(addr), &t);
            assert_eq!(verdict, op == Op::Eq);
        }
    }

    /// The v6 CIDR mask arithmetic: any prefix ≤ 128, membership
    /// reflexive; the `checked_shl` guard keeps the shift sound.
    #[kani::proof]
    fn ipv6_cidr_mask_is_safe_and_reflexive() {
        let octets: [u8; 16] = kani::any();
        let addr = Ipv6Addr::from(octets);
        let p = kani::any::<u8>();
        kani::assume(p <= 128);
        for op in [Op::Eq, Op::Ne] {
            let t = term(
                TermValue::Ipv6 {
                    addr,
                    prefix: Some(p),
                },
                op,
            );
            let verdict = eval(&Value::Ipv6(addr), &t);
            assert_eq!(verdict, op == Op::Eq);
        }
    }

    /// MAC equality and the type-mismatch fall-through: a MAC term
    /// against a non-MAC value is a clean `false` (never a panic);
    /// against the same MAC it's `true` under Eq.
    #[kani::proof]
    fn eval_type_mismatches_are_false() {
        let mac: [u8; 6] = kani::any();
        // MAC term vs Int value: false, no panic.
        let t = term(TermValue::Mac(mac), Op::Eq);
        assert!(!eval(&Value::Int(kani::any::<u128>()), &t));
        // Int term vs Bytes value: false.
        let t = term(TermValue::Int(1), Op::Eq);
        assert!(!eval(&Value::Bytes(Bytes::from_static(&[1])), &t));
        // HexPrefix term vs Int: false (the guard class).
        let t = term(TermValue::HexPrefix(Bytes::from_static(&[0xaa])), Op::Eq);
        assert!(!eval(&Value::Int(1), &t));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Codec, ReadOutcome, Registry};
    use crate::dissect::{Anomaly, LayerView};
    use crate::encode::EncodeCtx;
    use crate::error::EncodeError;
    use crate::schema::{LayerSchema, RecordSchema};
    use crate::spec::LayerSpec;
    use std::collections::BTreeMap;

    static TCP_FLAGS: &[&str] = &["cwr", "ece", "urg", "ack", "psh", "rst", "syn", "fin"];

    static TCP_SCHEMA: std::sync::LazyLock<LayerSchema> =
        std::sync::LazyLock::new(|| LayerSchema {
            kind: "tcp",
            rank: 30,
            parents: &["ipv4"],
            doc: "filter-test stand-in",
            fields: TCP_FIELDS.as_slice(),
            records: &[],
        });

    static IPV4_SCHEMA: std::sync::LazyLock<LayerSchema> =
        std::sync::LazyLock::new(|| LayerSchema {
            kind: "ipv4",
            rank: 20,
            parents: &["eth"],
            doc: "filter-test stand-in",
            fields: IPV4_FIELDS.as_slice(),
            records: &[],
        });

    static DNS_SCHEMA: std::sync::LazyLock<LayerSchema> =
        std::sync::LazyLock::new(|| LayerSchema {
            kind: "dns",
            rank: 40,
            parents: &["udp"],
            doc: "filter-test stand-in",
            fields: &[],
            records: DNS_AN_RECORDS,
        });

    static DNS_AN_FIELDS: &[FieldSchema] = &[
        FieldSchema {
            name: "name",
            kind: FieldKind::Str,
            bit_names: &[],
            default: Value::Str(std::borrow::Cow::Borrowed("")),
            required: false,
            doc: "",
        },
        FieldSchema {
            name: "ttl",
            kind: FieldKind::U32,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "",
        },
    ];

    static DNS_AN_RECORDS: &[RecordSchema] = &[RecordSchema {
        name: "an",
        fields: DNS_AN_FIELDS,
        settable: false,
        max: None,
        doc: "answers",
    }];

    fn dns_schema() -> &'static LayerSchema {
        &DNS_SCHEMA
    }

    static REG_DNS: SchemaCodec = SchemaCodec(dns_schema);

    static TCP_FIELDS: std::sync::LazyLock<Vec<FieldSchema>> = std::sync::LazyLock::new(|| {
        vec![
            FieldSchema {
                name: "sport",
                kind: FieldKind::U16,
                bit_names: &[],
                default: Value::Int(0),
                required: false,
                doc: "",
            },
            FieldSchema {
                name: "flags",
                kind: FieldKind::FlagSet,
                bit_names: TCP_FLAGS,
                default: Value::Int(0),
                required: false,
                doc: "",
            },
        ]
    });

    static IPV4_FIELDS: std::sync::LazyLock<Vec<FieldSchema>> = std::sync::LazyLock::new(|| {
        vec![
            FieldSchema {
                name: "src",
                kind: FieldKind::Ipv4,
                bit_names: &[],
                default: Value::Ipv4(std::net::Ipv4Addr::UNSPECIFIED),
                required: false,
                doc: "",
            },
            FieldSchema {
                name: "ttl",
                kind: FieldKind::U8,
                bit_names: &[],
                default: Value::Int(64),
                required: false,
                doc: "",
            },
            FieldSchema {
                name: "options",
                kind: FieldKind::Bytes,
                bit_names: &[],
                default: Value::Bytes(Bytes::new()),
                required: false,
                doc: "",
            },
        ]
    });

    static IPV6_FIELDS: std::sync::LazyLock<Vec<FieldSchema>> = std::sync::LazyLock::new(|| {
        vec![FieldSchema {
            name: "src",
            kind: FieldKind::Ipv6,
            bit_names: &[],
            default: Value::Ipv6(std::net::Ipv6Addr::UNSPECIFIED),
            required: false,
            doc: "",
        }]
    });

    static ETH_FIELDS: std::sync::LazyLock<Vec<FieldSchema>> = std::sync::LazyLock::new(|| {
        vec![FieldSchema {
            name: "dst",
            kind: FieldKind::Mac,
            bit_names: &[],
            default: Value::Mac([0; 6]),
            required: false,
            doc: "",
        }]
    });

    static IPV6_SCHEMA: std::sync::LazyLock<LayerSchema> =
        std::sync::LazyLock::new(|| LayerSchema {
            kind: "ipv6",
            rank: 20,
            parents: &["eth"],
            doc: "filter-test stand-in",
            fields: IPV6_FIELDS.as_slice(),
            records: &[],
        });

    static ETH_SCHEMA: std::sync::LazyLock<LayerSchema> =
        std::sync::LazyLock::new(|| LayerSchema {
            kind: "eth",
            rank: 10,
            parents: &[],
            doc: "filter-test stand-in",
            fields: ETH_FIELDS.as_slice(),
            records: &[],
        });

    struct SchemaCodec(fn() -> &'static LayerSchema);
    impl Codec for SchemaCodec {
        fn schema(&self) -> &'static LayerSchema {
            (self.0)()
        }
        fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
            Ok(0)
        }
        fn write(&self, _spec: &LayerSpec, _ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
            Ok(())
        }
        fn read<'a>(
            &self,
            _bytes: &'a [u8],
            _ctx: &mut crate::dissect::DecodeCtx<'a>,
        ) -> ReadOutcome {
            ReadOutcome::Empty
        }
    }

    fn tcp_schema() -> &'static LayerSchema {
        &TCP_SCHEMA
    }

    fn ipv4_schema() -> &'static LayerSchema {
        &IPV4_SCHEMA
    }

    static REG_TCP: SchemaCodec = SchemaCodec(tcp_schema);
    static REG_IPV4: SchemaCodec = SchemaCodec(ipv4_schema);
    static REG_IPV6: SchemaCodec = SchemaCodec(|| &IPV6_SCHEMA);
    static REG_ETH: SchemaCodec = SchemaCodec(|| &ETH_SCHEMA);

    fn test_registry() -> Registry {
        let mut r = Registry::empty();
        r.register(&REG_TCP);
        r.register(&REG_IPV4);
        r.register(&REG_DNS);
        r.register(&REG_IPV6);
        r.register(&REG_ETH);
        r
    }

    fn packet(layers: Vec<(&'static str, Vec<(&str, Value)>)>) -> DissectedPacket {
        DissectedPacket {
            start: layers.first().map_or("unknown", |l| l.0),
            layers: layers
                .into_iter()
                .map(|(kind, fields)| {
                    let mut map = BTreeMap::new();
                    for (k, v) in fields {
                        map.insert(k.to_string(), v);
                    }
                    LayerView {
                        kind,
                        span: 0..0,
                        field_spans: Default::default(),
                        fields: map,
                    }
                })
                .collect(),
            payload: Bytes::new(),
            anomalies: vec![Anomaly::new("x", "y")],
            frame: Bytes::new(),
            facts: Default::default(),
        }
    }

    #[test]
    fn parse_validates_against_schema() {
        let r = test_registry();
        assert!(Filter::parse(&r, "tcp.sport=80").is_ok());
        assert!(Filter::parse(&r, "tcp.sport=80 tcp.flags=syn,ack").is_ok());
        let e = Filter::parse(&r, "tcp.sportt=80").unwrap_err();
        assert!(e.to_string().contains("unknown field"), "{e}");
        let e = Filter::parse(&r, "ipx.sport=80").unwrap_err();
        assert!(e.to_string().contains("unknown layer"), "{e}");
        let e = Filter::parse(&r, "tcp.sport").unwrap_err();
        assert!(e.to_string().contains("expected <path><op><value>"), "{e}");
        let e = Filter::parse(&r, "tcp.flags=sny").unwrap_err();
        assert!(e.to_string().contains("unknown flag"), "{e}");
        let e = Filter::parse(&r, "tcp.flags.syn<1").unwrap_err();
        assert!(e.to_string().contains("only = and !="), "{e}");
        let e = Filter::parse(&r, "tcp.sport=abc").unwrap_err();
        assert!(e.to_string().contains("not a valid base"), "{e}");
    }

    #[test]
    fn ops_evaluate() {
        let r = test_registry();
        let p = packet(vec![(
            "tcp",
            vec![
                ("sport", Value::Int(443)),
                (
                    "flags",
                    Value::List(vec![Value::Str("syn".into()), Value::Str("ack".into())]),
                ),
            ],
        )]);
        assert!(Filter::parse(&r, "tcp.sport=443").unwrap().matches(&p));
        assert!(Filter::parse(&r, "tcp.sport!=444").unwrap().matches(&p));
        assert!(Filter::parse(&r, "tcp.sport>100").unwrap().matches(&p));
        assert!(Filter::parse(&r, "tcp.sport<=443").unwrap().matches(&p));
        assert!(!Filter::parse(&r, "tcp.sport<443").unwrap().matches(&p));
        assert!(Filter::parse(&r, "tcp.flags.syn=true").unwrap().matches(&p));
        assert!(Filter::parse(&r, "tcp.flags=ack").unwrap().matches(&p));
        assert!(!Filter::parse(&r, "tcp.flags=rst").unwrap().matches(&p));
        assert!(
            Filter::parse(&r, "tcp.sport=443 tcp.flags=ack")
                .unwrap()
                .matches(&p)
        );
        assert!(
            !Filter::parse(&r, "tcp.sport=443 tcp.flags=rst")
                .unwrap()
                .matches(&p)
        );
        // unknown-in-schema field → FilterError at startup (validated upfront)
        assert!(Filter::parse(&r, "tcp.dport=1").is_err());
        // schema-valid field absent from the packet → false
        let p2 = packet(vec![(
            "tcp",
            vec![("flags", Value::List(vec![Value::Str("syn".into())]))],
        )]);
        assert!(!Filter::parse(&r, "tcp.sport=80").unwrap().matches(&p2));
        // absent layer → false
        assert!(!Filter::parse(&r, "ipv4.ttl=64").unwrap().matches(&p));
        // empty filter matches everything
        assert!(Filter::parse(&r, "").unwrap().matches(&p));
    }

    #[test]
    fn ipv4_cidr_membership() {
        let r = test_registry();
        let p = packet(vec![(
            "ipv4",
            vec![("src", Value::Ipv4("10.0.0.1".parse().unwrap()))],
        )]);
        assert!(
            Filter::parse(&r, "ipv4.src=10.0.0.0/8")
                .unwrap()
                .matches(&p)
        );
        assert!(Filter::parse(&r, "ipv4.src=10.0.0.1").unwrap().matches(&p));
        assert!(
            !Filter::parse(&r, "ipv4.src=10.1.0.0/16")
                .unwrap()
                .matches(&p)
        );
        assert!(
            Filter::parse(&r, "ipv4.src!=10.1.0.0/16")
                .unwrap()
                .matches(&p)
        );
        let e = Filter::parse(&r, "ipv4.src<10.0.0.1").unwrap_err();
        assert!(e.to_string().contains("only = and !="), "{e}");
    }

    #[test]
    fn bytes_hex_prefix() {
        let r = test_registry();
        let p = packet(vec![(
            "ipv4",
            vec![(
                "options",
                Value::Bytes(Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef])),
            )],
        )]);
        assert!(
            Filter::parse(&r, "ipv4.options=hex:dead")
                .unwrap()
                .matches(&p)
        );
        assert!(
            Filter::parse(&r, "ipv4.options=deadbe")
                .unwrap()
                .matches(&p)
        );
        assert!(
            !Filter::parse(&r, "ipv4.options=hex:deadbeef00")
                .unwrap()
                .matches(&p)
        );
    }

    #[test]
    fn record_fields_filter_by_exact_index() {
        let r = test_registry();
        let p = packet(vec![(
            "dns",
            vec![
                ("an.0.name", Value::Str("example.com".into())),
                ("an.0.ttl", Value::Int(300)),
                ("an.1.name", Value::Str("other.test".into())),
            ],
        )]);
        // exact-index lookups hit the dissected keys directly
        assert!(
            Filter::parse(&r, "dns.an.0.name=example.com")
                .unwrap()
                .matches(&p)
        );
        assert!(
            !Filter::parse(&r, "dns.an.1.name=example.com")
                .unwrap()
                .matches(&p)
        );
        assert!(Filter::parse(&r, "dns.an.0.ttl=300").unwrap().matches(&p));
        assert!(!Filter::parse(&r, "dns.an.0.ttl<300").unwrap().matches(&p));
        // absent index → false (never-fatal)
        assert!(!Filter::parse(&r, "dns.an.2.ttl=1").unwrap().matches(&p));
        // AND across record fields
        assert!(
            Filter::parse(&r, "dns.an.0.name=example.com dns.an.0.ttl=300")
                .unwrap()
                .matches(&p)
        );
        assert!(
            !Filter::parse(&r, "dns.an.0.name=example.com dns.an.1.ttl=300")
                .unwrap()
                .matches(&p)
        );
        // grammar: unknown record field / wildcard rejected upfront
        assert!(Filter::parse(&r, "dns.an.0.nope=1").is_err());
        assert!(Filter::parse(&r, "dns.an.*.ttl=1").is_err());
        assert!(Filter::parse(&r, "dns.qd.0.name=x").is_err()); // no qd section here
    }

    #[test]
    fn is_empty_and_eq_ne_polarities() {
        let r = test_registry();
        // Empty filter: no terms, matches everything, is_empty == true.
        let empty = Filter::parse(&r, "").unwrap();
        assert!(empty.is_empty());
        assert!(empty.matches(&packet(vec![("tcp", vec![])])));
        // Non-empty: is_empty == false.
        let f = Filter::parse(&r, "tcp.sport=1").unwrap();
        assert!(!f.is_empty());
        let p = packet(vec![("tcp", vec![("sport", Value::Int(443))])]);
        // Eq / Ne on both polarities (packet 443).
        assert!(Filter::parse(&r, "tcp.sport=443").unwrap().matches(&p));
        assert!(!Filter::parse(&r, "tcp.sport=444").unwrap().matches(&p));
        assert!(!Filter::parse(&r, "tcp.sport!=443").unwrap().matches(&p));
        assert!(Filter::parse(&r, "tcp.sport!=444").unwrap().matches(&p));
    }

    #[test]
    fn int_ops_full_order() {
        let r = test_registry();
        // v = 100, want = 443: every op, both polarities.
        let p = packet(vec![("tcp", vec![("sport", Value::Int(100))])]);
        let m = |q: &str| Filter::parse(&r, q).unwrap().matches(&p);
        assert!(m("tcp.sport<443"));
        assert!(!m("tcp.sport<100")); // equal: < is false
        assert!(m("tcp.sport<=443"));
        assert!(m("tcp.sport<=100")); // equal: <= is true
        assert!(m("tcp.sport>44"));
        assert!(!m("tcp.sport>100")); // equal: > is false
        assert!(m("tcp.sport>=44"));
        assert!(m("tcp.sport>=100")); // equal: >= is true
        assert!(!m("tcp.sport>443"));
        assert!(!m("tcp.sport>=443"));
        assert!(!m("tcp.sport<44"));
        assert!(!m("tcp.sport<=44"));
        // ">=" grammar parses (the two-char spelling before its "<" prefix)
        assert!(Filter::parse(&r, "tcp.sport>=443").is_ok());
        // type mismatch: int term vs bytes value is false, never a panic
        let b = packet(vec![(
            "ipv4",
            vec![("options", Value::Bytes(Bytes::from_static(&[1])))],
        )]);
        assert!(!Filter::parse(&r, "tcp.sport=443").unwrap().matches(&b));
    }

    #[test]
    fn ipv4_cidr_boundaries() {
        let r = test_registry();
        let p = packet(vec![(
            "ipv4",
            vec![("src", Value::Ipv4("10.0.0.1".parse().unwrap()))],
        )]);
        let m = |q: &str| Filter::parse(&r, q).unwrap().matches(&p);
        assert!(m("ipv4.src=10.0.0.0/8")); // membership
        assert!(m("ipv4.src=10.0.0.0/16")); // high bits equal, low differ
        assert!(!m("ipv4.src=11.0.0.0/8")); // non-member same prefix len
        // exact /32: equal only
        assert!(m("ipv4.src=10.0.0.1/32"));
        assert!(!m("ipv4.src=10.0.0.2/32"));
        // /0 matches anything (the zero mask)
        assert!(m("ipv4.src=192.0.2.9/0"));
        assert!(m("ipv4.src=11.11.11.11/0"));
        // A /24 masks the low octet: membership on the prefix.
        assert!(m("ipv4.src=10.0.0.9/24"));
        assert!(!m("ipv4.src=10.0.1.9/24"));
        // Ne with a mask: complement of membership
        assert!(m("ipv4.src!=11.0.0.0/8"));
        assert!(!m("ipv4.src!=10.0.0.0/8"));
        // ordering ops are rejected at startup (validated upfront)
        assert!(Filter::parse(&r, "ipv4.src<10.0.0.1").is_err());
        // prefix bounds: > 32 is a startup error; 32 is the max
        assert!(Filter::parse(&r, "ipv4.src=10.0.0.1/33").is_err());
        assert!(Filter::parse(&r, "ipv4.src=10.0.0.1/32").is_ok());
    }

    #[test]
    fn ipv6_cidr_boundaries() {
        let r = test_registry();
        let p = packet(vec![(
            "ipv6",
            vec![("src", Value::Ipv6("2001:db8::1".parse().unwrap()))],
        )]);
        let m = |q: &str| Filter::parse(&r, q).unwrap().matches(&p);
        assert!(m("ipv6.src=2001:db8::/32")); // membership
        assert!(m("ipv6.src=2001:db8::/64"));
        assert!(!m("ipv6.src=2001:db9::/64")); // non-member same prefix len
        assert!(!m("ipv6.src=2001:db8::2/128")); // exact: unequal
        assert!(m("ipv6.src=2001:db8::1/128")); // exact: equal
        // /0 matches anything (the zero mask)
        assert!(m("ipv6.src=fe80::/0"));
        assert!(m("ipv6.src=::1/0"));
        // No prefix: plain equality (both polarities).
        assert!(m("ipv6.src=2001:db8::1"));
        assert!(!m("ipv6.src=2001:db8::2"));
        // Ne with a mask: complement
        assert!(m("ipv6.src!=2001:db9::/32"));
        assert!(!m("ipv6.src!=2001:db8::/32"));
        // ordering ops rejected upfront; prefix bounds 128
        assert!(Filter::parse(&r, "ipv6.src<::1").is_err());
        assert!(Filter::parse(&r, "ipv6.src=::1/129").is_err());
        assert!(Filter::parse(&r, "ipv6.src=::1/128").is_ok());
    }

    #[test]
    fn mac_filter_membership() {
        let r = test_registry();
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let p = packet(vec![("eth", vec![("dst", Value::Mac(mac))])]);
        let m = |q: &str| Filter::parse(&r, q).unwrap().matches(&p);
        assert!(m("eth.dst=aa:bb:cc:dd:ee:ff"));
        assert!(m("eth.dst=AA-BB-CC-DD-EE-FF")); // '-' separator parses
        assert!(!m("eth.dst=aa:bb:cc:dd:ee:fe"));
        assert!(!m("eth.dst!=aa:bb:cc:dd:ee:ff")); // Ne: equal is not a member
        assert!(m("eth.dst!=11:22:33:44:55:66")); // Ne: unequal is
        // a non-mac value against a mac term: false, never a panic
        let t = packet(vec![("eth", vec![("dst", Value::Int(1))])]);
        assert!(
            !Filter::parse(&r, "eth.dst=aa:bb:cc:dd:ee:ff")
                .unwrap()
                .matches(&t)
        );
        // non-mac grammar errors upfront
        assert!(Filter::parse(&r, "eth.dst=zz:bb:cc:dd:ee:ff").is_err());
        assert!(Filter::parse(&r, "eth.dst<aa:bb:cc:dd:ee:ff").is_err());
    }

    #[test]
    fn str_ordering_ops() {
        let r = test_registry();
        let p = packet(vec![(
            "dns",
            vec![("an.0.name", Value::Str("beta".into()))],
        )]);
        let m = |q: &str| Filter::parse(&r, q).unwrap().matches(&p);
        assert!(m("dns.an.0.name=beta"));
        assert!(!m("dns.an.0.name=alpha"));
        assert!(!m("dns.an.0.name!=beta")); // Ne: equal → false
        assert!(m("dns.an.0.name!=alpha"));
        assert!(m("dns.an.0.name<delta"));
        assert!(m("dns.an.0.name<=beta")); // equal → true
        assert!(!m("dns.an.0.name<beta")); // equal → false
        assert!(m("dns.an.0.name>alpha"));
        assert!(!m("dns.an.0.name>beta")); // equal → false
        assert!(m("dns.an.0.name>=beta")); // equal → true
        assert!(!m("dns.an.0.name>=delta"));
    }
}
