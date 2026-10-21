#![forbid(unsafe_code)]
//! wrex DNS codec (RFC 1035): rank 40, parent udp. One question is
//! craftable (`--dns-name/--dns-type/--dns-class` shorthand for
//! `qd.0.*` via the record-section schema); dissection renders the full
//! message: header fields, every question and every answer/authority/
//! additional record under indexed paths (`an.0.name`, `an.0.rdata`, …)
//! with compression pointers decoded. Records dissection is never
//! fatal: a bad section anomaly stops the layer with the parsed prefix.
//!
//! Tranche-3 deferrals (documented in the schema): multi-question
//! craft, settable answer records, typed multi-field rdata (MX/SOA/SRV
//! stay raw `Bytes`; AAAA rdata is typed ipv6 since tranche 7b), EDNS
//! crafting (OPT records are dissected, not craftable), the z/ad/cd
//! header bits.

pub mod name;
pub mod types;

use std::collections::BTreeMap;
use std::sync::LazyLock;

use bytes::{BufMut, Bytes};
use wrex_core::dissect::LayerView;
use wrex_core::encode::{EncodeCtx, flagset_or_default, int_or_default};
use wrex_core::error::DecodeError;
use wrex_core::schema::{FieldKind, FieldSchema, LayerSchema, RecordSchema};
use wrex_core::spec::LayerSpec;
use wrex_core::value::Value;
use wrex_core::{Anomaly, Codec, DecodeCtx, EncodeError, Next, ReadOutcome};

use crate::name::{decode_name, encode_name, name_wire_len};
use crate::types::{TYPE_A, TYPE_AAAA, parse_class, parse_type, render_class, render_type};

static FLAGS: &[&str] = &["qr", "aa", "tc", "rd", "ra"];

fn d(name: &'static str, kind: FieldKind, doc: &'static str, default: Value) -> FieldSchema {
    FieldSchema {
        name,
        kind,
        bit_names: &[],
        default,
        required: false,
        doc,
    }
}

static FIELDS: LazyLock<Vec<FieldSchema>> = LazyLock::new(|| {
    vec![
        d(
            "id",
            FieldKind::U16,
            "message id (craft: seeded by wrex query)",
            Value::Int(0),
        ),
        FieldSchema {
            name: "flags",
            kind: FieldKind::FlagSet,
            bit_names: FLAGS,
            default: Value::Int(0),
            required: false,
            doc: "flag aggregate [qr,aa,tc,rd,ra]; subpaths flags.<bit>",
        },
        d(
            "opcode",
            FieldKind::U8,
            "operation code (4 bits; 0 = QUERY)",
            Value::Int(0),
        ),
        d(
            "rcode",
            FieldKind::U8,
            "response code (4 bits; 0 = NOERROR)",
            Value::Int(0),
        ),
        d(
            "qdcount",
            FieldKind::U16,
            "question count (autofill: derived from the question)",
            Value::Int(0),
        ),
        d(
            "ancount",
            FieldKind::U16,
            "answer count (autofill: 0)",
            Value::Int(0),
        ),
        d(
            "nscount",
            FieldKind::U16,
            "authority count (autofill: 0)",
            Value::Int(0),
        ),
        d(
            "arcount",
            FieldKind::U16,
            "additional count (autofill: 0)",
            Value::Int(0),
        ),
    ]
});

static QD_FIELDS: LazyLock<Vec<FieldSchema>> = LazyLock::new(|| {
    vec![
        FieldSchema {
            name: "name",
            kind: FieldKind::Str,
            bit_names: &[],
            default: Value::Str(String::new()),
            required: false,
            doc: "question name, dotted presentation form (example.com)",
        },
        FieldSchema {
            name: "type",
            kind: FieldKind::Str,
            bit_names: &[],
            default: Value::Str("A".to_string()),
            required: false,
            doc: "question type: A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV, OPT, ANY, TYPE<n> or a number",
        },
        FieldSchema {
            name: "class",
            kind: FieldKind::Str,
            bit_names: &[],
            default: Value::Str("IN".to_string()),
            required: false,
            doc: "question class: IN, CH, HS, ANY, CLASS<n> or a number",
        },
    ]
});

static RR_FIELDS: LazyLock<Vec<FieldSchema>> = LazyLock::new(|| {
    vec![
        FieldSchema {
            name: "name",
            kind: FieldKind::Str,
            bit_names: &[],
            default: Value::Str(String::new()),
            required: false,
            doc: "record owner name (compression pointers resolved)",
        },
        FieldSchema {
            name: "type",
            kind: FieldKind::Str,
            bit_names: &[],
            default: Value::Str(String::new()),
            required: false,
            doc: "record type (A, CNAME, MX, …; TYPE<n> otherwise)",
        },
        FieldSchema {
            name: "class",
            kind: FieldKind::Str,
            bit_names: &[],
            default: Value::Str(String::new()),
            required: false,
            doc: "record class (IN, …; CLASS<n> otherwise)",
        },
        FieldSchema {
            name: "ttl",
            kind: FieldKind::U32,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "record TTL in seconds",
        },
        FieldSchema {
            name: "rdata",
            kind: FieldKind::Bytes,
            bit_names: &[],
            default: Value::Bytes(Bytes::new()),
            required: false,
            doc: "record data: A -> typed ipv4 value, AAAA -> typed ipv6 value (tranche 7b), CNAME/NS/PTR -> resolved name string, TXT -> raw bytes, others -> raw bytes hex (typed MX/SOA/SRV wait for later tranches)",
        },
    ]
});

static RECORDS: LazyLock<Vec<RecordSchema>> = LazyLock::new(|| {
    vec![
        RecordSchema {
            name: "qd",
            fields: QD_FIELDS.as_slice(),
            settable: true,
            max: Some(1),
            doc: "the question section (one question craftable at tranche 3)",
        },
        RecordSchema {
            name: "an",
            fields: RR_FIELDS.as_slice(),
            settable: false,
            max: None,
            doc: "answer records (dissect-only; indexed an.0.*, an.1.*, …)",
        },
        RecordSchema {
            name: "ns",
            fields: RR_FIELDS.as_slice(),
            settable: false,
            max: None,
            doc: "authority records (dissect-only; indexed ns.0.*, …)",
        },
        RecordSchema {
            name: "ar",
            fields: RR_FIELDS.as_slice(),
            settable: false,
            max: None,
            doc: "additional records (dissect-only; indexed ar.0.*, …; EDNS OPT lands here)",
        },
    ]
});

pub static SCHEMA: LazyLock<LayerSchema> = LazyLock::new(|| LayerSchema {
    kind: "dns",
    rank: 40,
    parents: &["udp"],
    doc: "DNS (RFC 1035) over UDP/53. Craft carries the 12-byte header plus one question (--dns-name anchors it; --dns-type/--dns-class default A/IN). Names encode uncompressed; dissection resolves compression pointers. Answers/authority/additional sections are dissect-only record sections with indexed paths (an.0.name, an.0.rdata, …). A rdata dissects typed ipv4, AAAA typed ipv6 (tranche 7b). Multi-question craft, settable answer records, typed MX/SOA/SRV rdata and EDNS crafting are tranche-3 deferrals.",
    fields: FIELDS.as_slice(),
    records: RECORDS.as_slice(),
});

/// DNS codec unit. Register as `&wrex_proto_dns::CODEC`.
pub struct DnsCodec;

pub static CODEC: DnsCodec = DnsCodec;

/// Aggregate flag bits (MSB-first `[qr,aa,tc,rd,ra]` → 0x10..0x01).
const AGG_QR: u16 = 0x10;
const AGG_AA: u16 = 0x08;
const AGG_TC: u16 = 0x04;
const AGG_RD: u16 = 0x02;
const AGG_RA: u16 = 0x01;

/// Question spec keys (record shorthand paths).
const QD_NAME: &str = "qd.0.name";
const QD_TYPE: &str = "qd.0.type";
const QD_CLASS: &str = "qd.0.class";

fn str_or(spec: &LayerSpec, key: &str, fallback: &str) -> String {
    match spec.fields.get(key) {
        Some(Value::Str(s)) => s.clone(),
        _ => fallback.to_string(),
    }
}

impl Codec for DnsCodec {
    fn schema(&self) -> &'static LayerSchema {
        &SCHEMA
    }

    fn header_len(&self, spec: &LayerSpec) -> Result<usize, EncodeError> {
        let base = 12;
        if let Some(Value::Str(n)) = spec.fields.get(QD_NAME) {
            let len = name_wire_len(n).map_err(|e| EncodeError::IncompatibleStack { detail: e })?;
            return Ok(base + len + 4);
        }
        Ok(base)
    }

    fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
        let af = ctx.autofill;
        let bad = |detail: String| EncodeError::IncompatibleStack { detail };

        // Header: id, flags word (aggregate bits + opcode/rcode), counts.
        let id = int_or_default(spec, &FIELDS[0], af) as u16;
        ctx.buf.put_u16(id);
        let agg = flagset_or_default(spec, &FIELDS[1], af) as u16;
        let mut word = 0u16;
        if agg & AGG_QR != 0 {
            word |= 0x8000;
        }
        if agg & AGG_AA != 0 {
            word |= 0x0400;
        }
        if agg & AGG_TC != 0 {
            word |= 0x0200;
        }
        if agg & AGG_RD != 0 {
            word |= 0x0100;
        }
        if agg & AGG_RA != 0 {
            word |= 0x0080;
        }
        let opcode = int_or_default(spec, &FIELDS[2], af) as u8;
        let rcode = int_or_default(spec, &FIELDS[3], af) as u8;
        word |= (opcode as u16 & 0x0F) << 11;
        word |= rcode as u16 & 0x0F;
        ctx.buf.put_u16(word);

        // The question: present iff the name is set; any qd.* field
        // without a name is an explicit error (not a silent root query).
        let qname = spec.fields.get(QD_NAME);
        let has_any_qd = [QD_NAME, QD_TYPE, QD_CLASS]
            .iter()
            .any(|k| spec.fields.contains_key(*k));
        if qname.is_none() && has_any_qd {
            return Err(EncodeError::Unfillable {
                field: "dns.qd.0.name".to_string(),
            });
        }
        let qdcount: u16 = match spec.fields.get("qdcount") {
            Some(Value::Int(v)) => *v as u16,
            _ if af => qname.is_some().into(),
            _ => 0,
        };
        let count_or = |key: &str| -> u16 {
            match spec.fields.get(key) {
                Some(Value::Int(v)) => *v as u16,
                _ => 0,
            }
        };
        ctx.buf.put_u16(qdcount);
        ctx.buf.put_u16(count_or("ancount"));
        ctx.buf.put_u16(count_or("nscount"));
        ctx.buf.put_u16(count_or("arcount"));

        // Question body (uncompressed name).
        if let Some(Value::Str(q)) = qname {
            let mut name_bytes = Vec::new();
            encode_name(q, &mut name_bytes).map_err(bad)?;
            let qtype = parse_type(&str_or(spec, QD_TYPE, "A"))
                .ok_or_else(|| bad(format!("unknown dns type `{}`", str_or(spec, QD_TYPE, "A"))))?;
            let qclass = parse_class(&str_or(spec, QD_CLASS, "IN")).ok_or_else(|| {
                bad(format!(
                    "unknown dns class `{}`",
                    str_or(spec, QD_CLASS, "IN")
                ))
            })?;
            ctx.buf.extend_from_slice(&name_bytes);
            ctx.buf.put_u16(qtype);
            ctx.buf.put_u16(qclass);
        }
        Ok(())
    }

    fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
        if bytes.is_empty() {
            return ReadOutcome::Empty;
        }
        if bytes.len() < 12 {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: "dns",
                    need: 12,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let mut fields = BTreeMap::new();
        let id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let word = u16::from_be_bytes([bytes[2], bytes[3]]);
        let opcode = (word >> 11) & 0x0F;
        let rcode = word & 0x0F;
        let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
        let ancount = u16::from_be_bytes([bytes[6], bytes[7]]);
        let nscount = u16::from_be_bytes([bytes[8], bytes[9]]);
        let arcount = u16::from_be_bytes([bytes[10], bytes[11]]);
        fields.insert("id".into(), Value::Int(id as u128));
        // Single-bit flags at word bits 15,10,9,8,7, in bit_names order.
        let mut names: Vec<Value> = Vec::new();
        if word & 0x8000 != 0 {
            names.push(Value::Str("qr".into()));
        }
        if word & 0x0400 != 0 {
            names.push(Value::Str("aa".into()));
        }
        if word & 0x0200 != 0 {
            names.push(Value::Str("tc".into()));
        }
        if word & 0x0100 != 0 {
            names.push(Value::Str("rd".into()));
        }
        if word & 0x0080 != 0 {
            names.push(Value::Str("ra".into()));
        }
        fields.insert("flags".into(), Value::List(names));
        fields.insert("opcode".into(), Value::Int(opcode as u128));
        fields.insert("rcode".into(), Value::Int(rcode as u128));
        fields.insert("qdcount".into(), Value::Int(qdcount as u128));
        fields.insert("ancount".into(), Value::Int(ancount as u128));
        fields.insert("nscount".into(), Value::Int(nscount as u128));
        fields.insert("arcount".into(), Value::Int(arcount as u128));

        let mut cursor = 12usize;

        // Question section.
        for i in 0..qdcount {
            match question_at(bytes, cursor) {
                Ok((q, next)) => {
                    fields.insert(format!("qd.{i}.name"), Value::Str(q.0));
                    fields.insert(format!("qd.{i}.type"), Value::Str(render_type(q.1)));
                    fields.insert(format!("qd.{i}.class"), Value::Str(render_class(q.2)));
                    cursor = next;
                }
                Err(e) => {
                    ctx.anomalies
                        .push(Anomaly::new(format!("dns.qd.{i}.name"), e));
                    return partial(ctx, fields, cursor);
                }
            }
        }
        // Answer / authority / additional sections.
        for (section, count) in [("an", ancount), ("ns", nscount), ("ar", arcount)] {
            for i in 0..count {
                match record_at(bytes, cursor) {
                    Ok((r, next)) => {
                        fields.insert(format!("{section}.{i}.name"), Value::Str(r.name));
                        fields.insert(
                            format!("{section}.{i}.type"),
                            Value::Str(render_type(r.rtype)),
                        );
                        fields.insert(
                            format!("{section}.{i}.class"),
                            Value::Str(render_class(r.rclass)),
                        );
                        fields.insert(format!("{section}.{i}.ttl"), Value::Int(r.ttl as u128));
                        fields.insert(
                            format!("{section}.{i}.rdata"),
                            typed_rdata(r.rtype, &r.rdata, bytes, r.rdata_at, ctx, section, i),
                        );
                        cursor = next;
                    }
                    Err(e) => {
                        ctx.anomalies
                            .push(Anomaly::new(format!("dns.{section}.{i}.name"), e));
                        return partial(ctx, fields, cursor);
                    }
                }
            }
        }

        let view = LayerView {
            kind: "dns",
            span: ctx.offset..ctx.offset + bytes.len(),
            field_spans: Default::default(),
            fields,
        };
        ReadOutcome::Layer(view, Some(Next::Payload))
    }
}

/// Build a partial (never-fatal) layer view for `bytes[..consumed]`.
fn partial(
    ctx: &mut DecodeCtx<'_>,
    fields: BTreeMap<String, Value>,
    consumed: usize,
) -> ReadOutcome {
    ReadOutcome::Layer(
        LayerView {
            kind: "dns",
            span: ctx.offset..ctx.offset + consumed,
            field_spans: Default::default(),
            fields,
        },
        Some(Next::Payload),
    )
}

/// Parse the question at `offset`: (name, type, class) + next offset.
fn question_at(bytes: &[u8], offset: usize) -> Result<((String, u16, u16), usize), String> {
    let (name, used) = decode_name(bytes, offset)?;
    let at = offset + used;
    if at + 4 > bytes.len() {
        return Err("truncated question (need 4 bytes for type/class)".to_string());
    }
    let qtype = u16::from_be_bytes([bytes[at], bytes[at + 1]]);
    let qclass = u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]);
    Ok(((name, qtype, qclass), at + 4))
}

struct Record {
    name: String,
    rtype: u16,
    rclass: u16,
    ttl: u32,
    rdata: Bytes,
    /// Absolute offset of `rdata` within the message (pointer targets
    /// are message-relative).
    rdata_at: usize,
}

/// Parse one RR at `offset`: owner, type, class, ttl, rdlength, rdata.
fn record_at(bytes: &[u8], offset: usize) -> Result<(Record, usize), String> {
    let (name, used) = decode_name(bytes, offset)?;
    let at = offset + used;
    if at + 10 > bytes.len() {
        return Err("truncated record (need type/class/ttl/rdlength)".to_string());
    }
    let rtype = u16::from_be_bytes([bytes[at], bytes[at + 1]]);
    let rclass = u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]);
    let ttl = u32::from_be_bytes([bytes[at + 4], bytes[at + 5], bytes[at + 6], bytes[at + 7]]);
    let rdlen = u16::from_be_bytes([bytes[at + 8], bytes[at + 9]]) as usize;
    let rdata_at = at + 10;
    if rdata_at + rdlen > bytes.len() {
        return Err(format!("rdata overruns the message (need {rdlen})"));
    }
    let rdata = Bytes::copy_from_slice(&bytes[rdata_at..rdata_at + rdlen]);
    Ok((
        Record {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
            rdata_at,
        },
        rdata_at + rdlen,
    ))
}

/// Typed rdata per the tranche-3 freeze: A → ipv4, CNAME/NS/PTR →
/// resolved name, everything else raw bytes. Bad A rdata degrades to
/// raw bytes + anomaly (never fatal).
fn typed_rdata(
    rtype: u16,
    rdata: &Bytes,
    message: &[u8],
    rdata_at: usize,
    ctx: &mut DecodeCtx<'_>,
    section: &str,
    index: u16,
) -> Value {
    use crate::types::{TYPE_CNAME, TYPE_NS, TYPE_PTR};
    match rtype {
        TYPE_A => {
            if rdata.len() == 4 {
                Value::Ipv4(std::net::Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                ))
            } else {
                ctx.anomalies.push(Anomaly::new(
                    format!("{section}.{index}.rdata"),
                    format!("A rdata must be 4 bytes, got {}", rdata.len()),
                ));
                Value::Bytes(rdata.clone())
            }
        }
        // Tranche 7b: AAAA rdata is typed ipv6 (FieldKind::Ipv6 landed).
        TYPE_AAAA => {
            if rdata.len() == 16 {
                let mut o = [0u8; 16];
                o.copy_from_slice(rdata);
                Value::Ipv6(std::net::Ipv6Addr::from(o))
            } else {
                ctx.anomalies.push(Anomaly::new(
                    format!("{section}.{index}.rdata"),
                    format!("AAAA rdata must be 16 bytes, got {}", rdata.len()),
                ));
                Value::Bytes(rdata.clone())
            }
        }
        TYPE_CNAME | TYPE_NS | TYPE_PTR => {
            // A name, possibly compressed (pointers are message-relative).
            match decode_name(message, rdata_at) {
                Ok((name, _)) => Value::Str(name),
                Err(e) => {
                    ctx.anomalies.push(Anomaly::new(
                        format!("{section}.{index}.rdata"),
                        format!("bad name in rdata: {e}"),
                    ));
                    Value::Bytes(rdata.clone())
                }
            }
        }
        _ => Value::Bytes(rdata.clone()),
    }
}

#[cfg(feature = "test-util")]
pub mod strategy {
    //! proptest strategies for `LayerSpec` (behind `test-util`).
    use proptest::prelude::*;
    use wrex_core::spec::LayerSpec;
    use wrex_core::value::Value;

    use crate::types::{parse_class, parse_type, render_class, render_type};

    /// Valid dns specs: random id, flag subsets, a question from a small
    /// realistic pool (canonical type/class names so roundtrips are
    /// exact).
    pub fn strategy() -> BoxedStrategy<LayerSpec> {
        let name = proptest::sample::select(vec![
            "example.com".to_string(),
            "a.b.example.com".to_string(),
            "localhost".to_string(),
            "x.io".to_string(),
            "sub.domain.example.co.uk".to_string(),
        ]);
        let qtype = proptest::sample::select(vec![
            "A", "AAAA", "MX", "TXT", "NS", "PTR", "SOA", "SRV", "CNAME",
        ]);
        let qclass = proptest::sample::select(vec!["IN", "CH", "HS"]);
        (any::<u16>(), any::<u8>(), name, qtype, qclass)
            .prop_map(|(id, mask, name, qtype, qclass)| {
                let mut fields = std::collections::BTreeMap::new();
                fields.insert("id".to_string(), Value::Int(id as u128));
                fields.insert("flags".to_string(), Value::Int(mask as u128));
                fields.insert("qd.0.name".to_string(), Value::Str(name));
                fields.insert(
                    "qd.0.type".to_string(),
                    Value::Str(render_type(parse_type(qtype).unwrap())),
                );
                fields.insert(
                    "qd.0.class".to_string(),
                    Value::Str(render_class(parse_class(qclass).unwrap())),
                );
                LayerSpec::with_fields("dns", fields)
            })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wrex_core::Registry;
    use wrex_core::encode::{EncodeOpts, encode};
    use wrex_core::spec::PacketSpec;

    fn registry() -> Registry {
        let mut r = Registry::empty();
        r.register(&CODEC);
        r
    }

    fn opts() -> EncodeOpts {
        EncodeOpts {
            autofill: true,
            ..Default::default()
        }
    }

    fn spec(fields: &[(&str, &str)]) -> LayerSpec {
        let mut map = BTreeMap::new();
        for (k, v) in fields {
            let value = match *k {
                "qd.0.name" | "qd.0.type" | "qd.0.class" => Value::Str((*v).to_string()),
                k if k.starts_with("flags.") => {
                    Value::Bool(v.parse::<bool>().map_err(|_| ()).unwrap_or(true))
                }
                _ => Value::Int(v.parse::<u128>().unwrap()),
            };
            map.insert(k.to_string(), value);
        }
        LayerSpec::with_fields("dns", map)
    }

    #[test]
    fn golden_query() {
        let enc = encode(
            &registry(),
            &PacketSpec::new(
                vec![spec(&[
                    ("id", "4660"),
                    ("flags.rd", "1"), // per-bit subpath merges into the aggregate
                    ("qd.0.name", "example.com"),
                    ("qd.0.type", "MX"),
                ])],
                None,
            ),
            &opts(),
        )
        .unwrap();
        assert_eq!(
            hex::encode(&enc.bytes),
            "123401000001000000000000\
             076578616d706c6503636f6d00000f0001"
                .replace('\n', "")
        );
        // id=0x1234, flags=0x0100 (rd), qdcount=1, name, type MX(15), class IN(1)
        assert_eq!(u16::from_be_bytes([enc.bytes[0], enc.bytes[1]]), 0x1234);
        assert_eq!(u16::from_be_bytes([enc.bytes[2], enc.bytes[3]]), 0x0100);
        assert_eq!(u16::from_be_bytes([enc.bytes[4], enc.bytes[5]]), 1);
    }

    #[test]
    fn header_only_and_defaults() {
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec(&[("id", "7")])], None),
            &opts(),
        )
        .unwrap();
        assert_eq!(enc.bytes.len(), 12);
        // no question, no autofill quirks: qdcount 0
        assert_eq!(u16::from_be_bytes([enc.bytes[4], enc.bytes[5]]), 0);
        // default type/class are NOT applied when there is no question
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "dns");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.layers[0].fields.get("id"), Some(&Value::Int(7)));
    }

    #[test]
    fn question_requires_name() {
        // qd.0.type without qd.0.name → explicit unfillable
        let e = encode(
            &registry(),
            &PacketSpec::new(vec![spec(&[("qd.0.type", "MX")])], None),
            &opts(),
        )
        .unwrap_err();
        assert!(matches!(e, EncodeError::Unfillable { field } if field == "dns.qd.0.name"));
    }

    #[test]
    fn bad_type_and_bad_name_are_usage_errors() {
        let e = encode(
            &registry(),
            &PacketSpec::new(
                vec![spec(&[("qd.0.name", "x.io"), ("qd.0.type", "BOGUS")])],
                None,
            ),
            &opts(),
        )
        .unwrap_err();
        assert!(e.to_string().contains("unknown dns type"), "{e}");
        let e = encode(
            &registry(),
            &PacketSpec::new(vec![spec(&[("qd.0.name", "a..b")])], None),
            &opts(),
        )
        .unwrap_err();
        assert!(e.to_string().contains("empty label"), "{e}");
    }

    #[test]
    fn explicit_counts_kept_unvalidated() {
        let enc = encode(
            &registry(),
            &PacketSpec::new(
                vec![spec(&[
                    ("id", "1"),
                    ("ancount", "9"), // deliberately inconsistent
                    ("qd.0.name", "x.io"),
                ])],
                None,
            ),
            &opts(),
        )
        .unwrap();
        assert_eq!(u16::from_be_bytes([enc.bytes[6], enc.bytes[7]]), 9);
        // dissection reports the mismatch as an anomaly (never fatal)
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "dns");
        assert!(
            p.anomalies.iter().any(|a| a.path == "dns.an.0.name"),
            "{:?}",
            p.anomalies
        );
    }

    #[test]
    fn dissect_full_reply_with_records() {
        // Hand-built reply: qr/rd/ra set, one A answer whose name is a
        // compression pointer to the question (0xC00C).
        let mut msg = vec![
            0xab, 0xcd, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        msg.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01"); // question
        msg.extend_from_slice(&[0xC0, 0x0C]); // answer name → question
        msg.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
        msg.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // ttl 300
        msg.extend_from_slice(&[0x00, 0x04, 1, 2, 3, 4]); // rdlen 4, 1.2.3.4

        let p = wrex_core::dissect::dissect(&registry(), &msg, "dns");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        let l = &p.layers[0];
        assert_eq!(l.kind, "dns");
        assert_eq!(l.fields.get("id"), Some(&Value::Int(0xabcd)));
        assert!(matches!(
            l.fields.get("flags"),
            Some(Value::List(items)) if items == &vec![
                Value::Str("qr".into()),
                Value::Str("rd".into()),
                Value::Str("ra".into()),
            ]
        ));
        assert_eq!(
            l.fields.get("qd.0.name"),
            Some(&Value::Str("example.com".into()))
        );
        assert_eq!(l.fields.get("qd.0.type"), Some(&Value::Str("A".into())));
        assert_eq!(
            l.fields.get("an.0.name"),
            Some(&Value::Str("example.com".into()))
        );
        assert_eq!(l.fields.get("an.0.ttl"), Some(&Value::Int(300)));
        assert_eq!(
            l.fields.get("an.0.rdata"),
            Some(&Value::Ipv4("1.2.3.4".parse().unwrap()))
        );
        // fully consumed: no payload remainder
        assert!(p.payload.is_empty());
    }

    #[test]
    fn dissect_partial_never_fatal() {
        // header claims 1 question, message ends mid-name
        let msg = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
        ];
        let p = wrex_core::dissect::dissect(&registry(), &msg, "dns");
        // parsed prefix (header) + anomaly + the tail as payload
        assert!(!p.anomalies.is_empty());
        assert_eq!(p.layers[0].span, 0..12);
        assert_eq!(p.payload[..], [0x07]);
        assert_eq!(p.layers[0].fields.get("id"), Some(&Value::Int(1)));
    }

    #[test]
    fn dissect_opt_and_txt_records_raw() {
        // arcount=1, OPT record with 12-byte rdata
        let mut msg = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        msg.push(0x00); // root name
        msg.extend_from_slice(&[0x00, 0x29]); // OPT
        msg.extend_from_slice(&[0x10, 0x00]); // "class" = udp payload size 4096
        msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // ttl = ext flags/rcode
        msg.extend_from_slice(&[0x00, 0x0C]); // rdlen 12
        msg.extend_from_slice(&[
            0x00, 0x0A, 0x00, 0x08, 0x9c, 0x18, 0x00, 0x08, 0x00, 0x08, 0x00, 0x17,
        ]);
        let p = wrex_core::dissect::dissect(&registry(), &msg, "dns");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        let l = &p.layers[0];
        assert_eq!(l.fields.get("ar.0.type"), Some(&Value::Str("OPT".into())));
        assert!(matches!(l.fields.get("ar.0.rdata"), Some(Value::Bytes(_))));
    }

    #[test]
    fn header_len_reflects_question() {
        let s = spec(&[("qd.0.name", "example.com")]);
        assert_eq!(CODEC.header_len(&s).unwrap(), 12 + 13 + 4);
        assert_eq!(CODEC.header_len(&spec(&[])).unwrap(), 12);
    }
}
