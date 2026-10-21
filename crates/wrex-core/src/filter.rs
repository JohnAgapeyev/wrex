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

    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "=" => Self::Eq,
            "!=" => Self::Ne,
            "<=" => Self::Le,
            ">=" => Self::Ge,
            "<" => Self::Lt,
            ">" => Self::Gt,
            _ => return None,
        })
    }
    fn spelling(self) -> &'static str {
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
                    Value::Str(s) => Some(s.as_str()),
                    _ => None,
                })
                .collect();
            eq(want.iter().all(|w| names.contains(&w.as_str())))
        }
        (TermValue::FlagBit { name, set }, Value::List(items)) => {
            let names: Vec<&str> = items
                .iter()
                .filter_map(|v| match v {
                    Value::Str(s) => Some(s.as_str()),
                    _ => None,
                })
                .collect();
            eq(names.contains(&name.as_str()) == *set)
        }
        (TermValue::Str(want), Value::Str(v)) => match t.op {
            Op::Eq => v == want,
            Op::Ne => v != want,
            Op::Lt => v < want,
            Op::Le => v <= want,
            Op::Gt => v > want,
            Op::Ge => v >= want,
        },
        _ => false,
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
            default: Value::Str(String::new()),
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

    fn test_registry() -> Registry {
        let mut r = Registry::empty();
        r.register(&REG_TCP);
        r.register(&REG_IPV4);
        r.register(&REG_DNS);
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
                        fields: map,
                    }
                })
                .collect(),
            payload: Bytes::new(),
            anomalies: vec![Anomaly::new("x", "y")],
            frame: Bytes::new(),
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
}
