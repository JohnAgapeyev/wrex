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

use bytes::{BufMut, Bytes};
use wrex_core::dissect::{FieldSpan, LayerView};
use wrex_core::encode::{EncodeCtx, flagset_or_default, int_or_default};
use wrex_core::error::DecodeError;
use wrex_core::schema::{FieldKind, FieldSchema, LayerSchema, Layout, RecordSchema};
use wrex_core::spec::LayerSpec;
use wrex_core::value::Value;
use wrex_core::{Anomaly, Codec, DecodeCtx, EncodeError, Next, ReadOutcome};

use std::borrow::Cow;

use crate::name::{decode_name, encode_name, name_wire_len};
use crate::types::{
    TYPE_A, TYPE_AAAA, TYPE_OPT, parse_class, parse_type, render_class, render_type,
};

/// Header flag bits (MSB-first aggregate order — `bit_names[0]` ↔ the
/// highest aggregate bit). Tranche 20a-1 closes the tranche-3 deferral:
/// `ad`/`cd` join the aggregate; `z` (RFC 1035 §4.1.1, must be zero)
/// is deliberately **not** craftable — dissection renders `flags.z` and
/// a never-fatal anomaly when a peer sets it.
static FLAGS: &[&str] = &["qr", "aa", "tc", "rd", "ra", "ad", "cd"];

const fn d(name: &'static str, kind: FieldKind, doc: &'static str, default: Value) -> FieldSchema {
    FieldSchema {
        name,
        kind,
        bit_names: &[],
        default,
        required: false,
        doc,
    }
}

static FIELDS: [FieldSchema; 13] = [
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
        doc: "flag aggregate [qr,aa,tc,rd,ra,ad,cd]; subpaths flags.<bit>",
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
        "answer count (autofill: derived from an.N.* records)",
        Value::Int(0),
    ),
    d(
        "nscount",
        FieldKind::U16,
        "authority count (autofill: derived from ns.N.* records)",
        Value::Int(0),
    ),
    d(
        "arcount",
        FieldKind::U16,
        "additional count (autofill: derived from ar.N.* records + the EDNS sugar)",
        Value::Int(0),
    ),
    // --- EDNS0 sugar (tranche 20a-1; craft-only inputs: the OPT
    // pseudo-record's wire lives under ar.N.*, never at these keys ---
    // dissection renders the typed OPT there instead). ---
    d(
        "edns",
        FieldKind::U16,
        "EDNS0 udp payload size: > 0 appends one OPT pseudo-record to ar (tranche 20a-1)",
        Value::Int(0),
    ),
    d(
        "edns_ext_rcode",
        FieldKind::U8,
        "EDNS0 extended rcode byte (8 high bits; --dns-edns implies 0)",
        Value::Int(0),
    ),
    d(
        "edns_version",
        FieldKind::U8,
        "EDNS0 version byte (0 = EDNS0)",
        Value::Int(0),
    ),
    d(
        "edns_do",
        FieldKind::U8,
        "EDNS0 DO bit (0/1, DNSSEC OK; RFC 6891 §6.1.2)",
        Value::Int(0),
    ),
    d(
        "edns_options",
        FieldKind::Str,
        "OPT option TLVs, comma-separated: nsid:HEX, cookie:HEX[:HEX], ecs:IP[/PREFIX[/SCOPE]], raw:CODE:HEX",
        Value::Str(Cow::Borrowed("")),
    ),
];

static QD_FIELDS: [FieldSchema; 3] = [
    FieldSchema {
        name: "name",
        kind: FieldKind::Str,
        bit_names: &[],
        default: Value::Str(Cow::Borrowed("")),
        required: false,
        doc: "question name, dotted presentation form (example.com)",
    },
    FieldSchema {
        name: "type",
        kind: FieldKind::Str,
        bit_names: &[],
        default: Value::Str(Cow::Borrowed("A")),
        required: false,
        doc: "question type: A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV, OPT, ANY, TYPE<n> or a number",
    },
    FieldSchema {
        name: "class",
        kind: FieldKind::Str,
        bit_names: &[],
        default: Value::Str(Cow::Borrowed("IN")),
        required: false,
        doc: "question class: IN, CH, HS, ANY, CLASS<n> or a number",
    },
];

static RR_FIELDS: [FieldSchema; 5] = [
    FieldSchema {
        name: "name",
        kind: FieldKind::Str,
        bit_names: &[],
        default: Value::Str(Cow::Borrowed("")),
        required: false,
        doc: "record owner name (compression pointers resolved)",
    },
    FieldSchema {
        name: "type",
        kind: FieldKind::Str,
        bit_names: &[],
        default: Value::Str(Cow::Borrowed("")),
        required: false,
        doc: "record type (A, CNAME, MX, …; TYPE<n> otherwise)",
    },
    FieldSchema {
        name: "class",
        kind: FieldKind::Str,
        bit_names: &[],
        default: Value::Str(Cow::Borrowed("")),
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
        doc: "record data: A -> typed ipv4 value, AAAA -> typed ipv6 value (tranche 7b), CNAME/NS/PTR -> resolved name string, TXT -> raw bytes, others -> raw bytes hex; typed subfields ride an|ns|ar.N.<type>.* paths (tranche 20a-2)",
    },
];

static RECORDS: [RecordSchema; 4] = [
    RecordSchema {
        name: "qd",
        fields: &QD_FIELDS,
        settable: true,
        max: Some(1),
        doc: "the question section (one question craftable at tranche 3)",
    },
    RecordSchema {
        name: "an",
        fields: &RR_FIELDS,
        settable: true,
        max: None,
        doc: "answer records (tranche 20a-2: settable through index paths an.0.*, …)",
    },
    RecordSchema {
        name: "ns",
        fields: &RR_FIELDS,
        settable: true,
        max: None,
        doc: "authority records (tranche 20a-2: settable through index paths ns.0.*, …)",
    },
    RecordSchema {
        name: "ar",
        fields: &RR_FIELDS,
        settable: true,
        max: None,
        doc: "additional records (tranche 20a-2: settable through index paths ar.0.*, …; the EDNS OPT pseudo-record lands here)",
    },
];

/// The kind string this codec implements (ADR 3): the vocabulary is
/// compile-checked and symmetric across codecs.
pub const KIND: &str = "dns";

pub static SCHEMA: LayerSchema = LayerSchema {
    kind: KIND,
    rank: 40,
    parents: &[wrex_proto_udp::KIND],
    doc: "DNS (RFC 1035) over UDP/53. Craft carries the 12-byte header, one question (--dns-name anchors it), every an/ns/ar record present in the spec (indexed paths an.0.*, …, tranche 20a-2), and the EDNS0 sugar (--dns-edns SIZE and friends append one OPT pseudo-record to ar, tranche 20a-1). Names encode uncompressed; dissection resolves compression pointers. A rdata dissects typed ipv4, AAAA typed ipv6 (tranche 7b); CNAME/NS/PTR rdata resolve to names; every other rdata stays raw bytes with typed subfields under an|ns|ar.N.<type>.* paths (MX preference, SOA timers, SVCB/HTTPS params, DNSSEC read-side shapes — tranche 20a-2). Multi-question craft and DNSSEC validation stay deferred.",
    fields: &FIELDS,
    records: &RECORDS,
};

/// DNS codec unit. Register via [`register`] (the ADR-3 closure);
/// bespoke registries may use `&wrex_proto_dns::CODEC` directly.
pub struct DnsCodec;

pub static CODEC: DnsCodec = DnsCodec;

/// ADR 3 registration closure: register self (dedup-guarded via
/// [`Registry::get`]), then the parent crates'. Self-first keeps
/// `standard()`'s fixed registration order byte-identical —
/// presence, not order, is the guarantee.
pub fn register(r: &mut wrex_core::Registry) {
    if r.get(KIND).is_none() {
        r.register(&CODEC);
    }
    wrex_proto_udp::register(r);
}

/// Aggregate flag bits (MSB-first `[qr,aa,tc,rd,ra,ad,cd]` → 0x40..0x01;
/// the 7-bit unit, `bit_names[0]` ↔ the highest bit — `flagset_or_default`
/// and `serialize_field_value` share the convention). Word mapping (RFC 1035
/// §4.1.1): qr=15, aa=10, tc=9, rd=8, ra=7, ad=5, cd=4.
const AGG_QR: u16 = 0x40;
const AGG_AA: u16 = 0x20;
const AGG_TC: u16 = 0x10;
const AGG_RD: u16 = 0x08;
const AGG_RA: u16 = 0x04;
const AGG_AD: u16 = 0x02;
const AGG_CD: u16 = 0x01;

/// Question spec keys (record shorthand paths).
const QD_NAME: &str = "qd.0.name";
const QD_TYPE: &str = "qd.0.type";
const QD_CLASS: &str = "qd.0.class";

fn str_or(spec: &LayerSpec, key: &str, fallback: &str) -> String {
    match spec.fields.get(key) {
        Some(Value::Str(s)) => s.to_string(),
        _ => fallback.to_string(),
    }
}

/// The three settable record sections (tranche 20a-2).
const SECTIONS: [&str; 3] = ["an", "ns", "ar"];

/// One crafted record's wire parts (tranche 20a-2).
struct CraftedRecord {
    /// Owner name, wire form (uncompressed — craft never compresses).
    name: Vec<u8>,
    rtype: u16,
    class: u16,
    ttl: u32,
    rdata: Vec<u8>,
    /// OPT pseudo-record (one per message, RFC 6891 §6.1.1).
    opt: bool,
}

/// Parse the spec's index-path records for `section` into wire parts,
/// contiguous from index 0 (an index gap ends the section — the
/// tranche-11b-β count rule: the caller patches counts explicitly).
/// Tranche 20a-2: `an`/`ns`/`ar` close the tranche-3 settable-answer
/// deferral; rdata rides the raw `hex:` grammar (typed rdata *craft*
/// stays deferred — the read side types, the write side stays bytes).
fn crafted_records(spec: &LayerSpec, section: &str) -> Result<Vec<CraftedRecord>, EncodeError> {
    let bad = |detail: String| EncodeError::IncompatibleStack { detail };
    let mut out = Vec::new();
    for n in 0usize.. {
        let prefix = format!("{section}.{n}.");
        if !spec.fields.keys().any(|k| k.starts_with(&prefix)) {
            break;
        }
        let name_key = format!("{prefix}name");
        // A record without a type is a pointed gap (the count would lie).
        let type_key = format!("{prefix}type");
        let Some(Value::Str(rt)) = spec.fields.get(type_key.as_str()) else {
            return Err(EncodeError::Unfillable {
                field: format!("dns.{section}.{n}.type"),
            });
        };
        let rt = rt.to_string();
        let rtype = parse_type(&rt).ok_or_else(|| bad(format!("unknown dns type `{rt}`")))?;
        let name = match spec.fields.get(name_key.as_str()) {
            Some(Value::Str(s)) => s.to_string(),
            _ => String::new(),
        };
        let mut name_bytes = Vec::new();
        encode_name(&name, &mut name_bytes).map_err(bad)?;
        let opt = rtype == TYPE_OPT;
        if opt && !name.is_empty() {
            // The OPT owner is the root (RFC 6891 §6.1.2); keep the
            // pseudo-record honest on the explicit path too.
            return Err(bad(format!(
                "dns.{section}.{n}.name must be the root for an OPT record (got `{name}`)"
            )));
        }
        // OPT's class field IS the udp payload size: default 4096 (the
        // sugar default), not IN, when unset.
        let class_key = format!("{prefix}class");
        let class = match spec.fields.get(class_key.as_str()) {
            Some(Value::Str(c)) => {
                let c = c.to_string();
                if opt {
                    c.parse::<u16>().map_err(|_| {
                        bad(format!(
                            "dns.{section}.{n}.class is the udp payload size for OPT (got `{c}`)"
                        ))
                    })?
                } else {
                    parse_class(&c).ok_or_else(|| bad(format!("unknown dns class `{c}`")))?
                }
            }
            _ if opt => 4096,
            _ => crate::types::CLASS_IN,
        };
        let ttl_key = format!("{prefix}ttl");
        let ttl = match spec.fields.get(ttl_key.as_str()) {
            Some(Value::Int(v)) => *v as u32,
            _ => 0,
        };
        let rdata_key = format!("{prefix}rdata");
        let rdata = match spec.fields.get(rdata_key.as_str()) {
            Some(Value::Bytes(b)) => b.to_vec(),
            // A non-bytes rdata (an int on a Bytes field, …) is a pointed
            // gap, never a silent coercion.
            Some(_) => {
                return Err(EncodeError::Unfillable {
                    field: format!("dns.{section}.{n}.rdata"),
                });
            }
            _ => Vec::new(),
        };
        out.push(CraftedRecord {
            name: name_bytes,
            rtype,
            class,
            ttl,
            rdata,
            opt,
        });
    }
    Ok(out)
}

/// The EDNS0 sugar (tranche 20a-1): any `--dns-edns*` knob appends one
/// OPT pseudo-record to the ar section. The sugar fields are
/// craft-only inputs — never rendered by dissection (the typed OPT
/// lives under `ar.N.*` there instead).
fn append_edns(spec: &LayerSpec, ar: &mut Vec<CraftedRecord>) -> Result<(), EncodeError> {
    let bad = |detail: String| EncodeError::IncompatibleStack { detail };
    let int = |name: &str, field: &FieldSchema| -> u128 {
        match spec.fields.get(name) {
            Some(Value::Int(v)) => *v,
            // Non-int on an int field: the default (the flat-field value
            // grammar rejects it upstream).
            _ => match field.default {
                Value::Int(d) => d,
                _ => 0,
            },
        }
    };
    let mut size = int("edns", &FIELDS[8]) as u16;
    let ext_rcode = int("edns_ext_rcode", &FIELDS[9]) as u32;
    let version = int("edns_version", &FIELDS[10]) as u32;
    let do_bit = int("edns_do", &FIELDS[11]);
    let options = str_or(spec, "edns_options", "");
    let active = size > 0 || ext_rcode > 0 || version > 0 || do_bit > 0 || !options.is_empty();
    if !active {
        return Ok(());
    }
    if size == 0 {
        // Knobs without --dns-edns: advertise the dig-style default size.
        size = 4096;
    }
    if do_bit > 1 {
        return Err(bad(format!("--dns-edns-do is 0 or 1 (got {do_bit})")));
    }
    let rdata = encode_edns_options(&options).map_err(bad)?;
    ar.push(CraftedRecord {
        name: vec![0], // the root
        rtype: TYPE_OPT,
        class: size,
        ttl: ((ext_rcode & 0xFF) << 24) | ((version & 0xFF) << 16) | (u32::from(do_bit == 1) << 15),
        rdata,
        opt: true,
    });
    Ok(())
}

/// The `--dns-edns-options` TLV grammar → wire: comma-separated
/// `nsid:HEX`, `cookie:HEX[:HEX]`, `ecs:IP[/PREFIX[/SCOPE]]` (the
/// RFC 7871 §4 subset — `raw:CODE:HEX` covers the rest; the dhcp
/// `options`-grammar shape).
fn encode_edns_options(raw: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for part in raw.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (name, rest) = part
            .split_once(':')
            .ok_or_else(|| format!("bad edns option `{part}` (want name:value)"))?;
        match name {
            "nsid" => {
                let v = hex::decode(rest).map_err(|e| format!("bad nsid hex: {e}"))?;
                out.extend_from_slice(&[0, 3]);
                out.extend_from_slice(&(v.len() as u16).to_be_bytes());
                out.extend_from_slice(&v);
            }
            "cookie" => {
                let mut it = rest.splitn(2, ':');
                let client = hex::decode(it.next().unwrap_or_default())
                    .map_err(|e| format!("bad cookie hex: {e}"))?;
                let server = match it.next() {
                    Some(s) => Some(hex::decode(s).map_err(|e| format!("bad cookie hex: {e}"))?),
                    None => None,
                };
                let v: Vec<u8> = client
                    .iter()
                    .chain(server.unwrap_or_default().iter())
                    .copied()
                    .collect();
                out.extend_from_slice(&[0, 10]);
                out.extend_from_slice(&(v.len() as u16).to_be_bytes());
                out.extend_from_slice(&v);
            }
            "ecs" => {
                // ecs:ADDR[/PREFIX[/SCOPE]] — RFC 7871 §4 wire: family(2),
                // source prefix(1), scope(1), addr (truncated to the prefix).
                let mut it = rest.split('/');
                let addr: std::net::IpAddr = it
                    .next()
                    .unwrap_or_default()
                    .parse()
                    .map_err(|e| format!("bad ecs address: {e}"))?;
                let (family, bytes): (u16, &[u8]) = match addr {
                    std::net::IpAddr::V4(a) => (1, &a.octets()),
                    std::net::IpAddr::V6(a) => (2, &a.octets()),
                };
                let max = if family == 1 { 32 } else { 128 };
                let prefix: usize = match it.next() {
                    Some(p) => p.parse().map_err(|e| format!("bad ecs prefix: {e}"))?,
                    None => max,
                };
                let scope: u8 = match it.next() {
                    Some(s) => s.parse().map_err(|e| format!("bad ecs scope: {e}"))?,
                    None => 0,
                };
                if prefix > max {
                    return Err(format!("ecs prefix {prefix} exceeds the family"));
                }
                let keep = prefix.div_ceil(8);
                out.extend_from_slice(&[0, 8]);
                out.extend_from_slice(&(4 + keep as u16).to_be_bytes());
                out.extend_from_slice(&family.to_be_bytes());
                out.push(prefix as u8);
                out.push(scope);
                out.extend_from_slice(&bytes[..keep]);
            }
            "raw" => {
                let (code, hexdata) = rest
                    .split_once(':')
                    .ok_or_else(|| format!("bad raw option `{rest}` (want raw:CODE:HEX)"))?;
                let code: u16 = code.parse().map_err(|e| format!("bad raw code: {e}"))?;
                let v = hex::decode(hexdata).map_err(|e| format!("bad raw hex: {e}"))?;
                out.extend_from_slice(&code.to_be_bytes());
                out.extend_from_slice(&(v.len() as u16).to_be_bytes());
                out.extend_from_slice(&v);
            }
            other => {
                return Err(format!(
                    "unknown edns option `{other}` (nsid, cookie, ecs, raw)"
                ));
            }
        }
    }
    Ok(out)
}

impl Codec for DnsCodec {
    fn schema(&self) -> &'static LayerSchema {
        &SCHEMA
    }

    fn header_len(&self, spec: &LayerSpec) -> Result<usize, EncodeError> {
        let base = 12;
        let mut len = base;
        if let Some(Value::Str(n)) = spec.fields.get(QD_NAME) {
            let qlen =
                name_wire_len(n).map_err(|e| EncodeError::IncompatibleStack { detail: e })?;
            len += qlen + 4;
        }
        // Tranche 20a-1/20a-2: crafted records + the EDNS sugar ride the
        // same accounting (the udp parent's length autofill wants the
        // truth).
        let mut crafted = [Vec::new(), Vec::new(), Vec::new()];
        for (i, section) in SECTIONS.iter().enumerate() {
            crafted[i] = crafted_records(spec, section)?;
        }
        append_edns(spec, &mut crafted[2])?;
        for section in &crafted {
            for r in section {
                len += r.name.len() + 10 + r.rdata.len();
            }
        }
        Ok(len)
    }

    fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
        let af = ctx.autofill;
        let bad = |detail: String| EncodeError::IncompatibleStack { detail };

        // Header: id, flags word (aggregate bits + ad/cd, tranche
        // 20a-1 + opcode/rcode), counts.
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
        // Tranche 20a-1: ad (bit 5) / cd (bit 4) — the recorded tranche-3
        // header-bit deferral closed.
        if agg & AGG_AD != 0 {
            word |= 0x0020;
        }
        if agg & AGG_CD != 0 {
            word |= 0x0010;
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
        // Tranche 20a-2: crafted record sections + the EDNS sugar decide
        // the autofilled counts; explicit counts keep winning (unvalidated,
        // the tranche-3 rule).
        let mut crafted = [Vec::new(), Vec::new(), Vec::new()];
        for (i, section) in SECTIONS.iter().enumerate() {
            crafted[i] = crafted_records(spec, section)?;
        }
        append_edns(spec, &mut crafted[2])?;
        // One OPT pseudo-record per message (RFC 6891 §6.1.1): the sugar
        // and the explicit index paths share the rule.
        let opts = crafted
            .iter()
            .flat_map(|s| s.iter())
            .filter(|r| r.opt)
            .count();
        if opts > 1 {
            return Err(bad(format!(
                "at most one OPT pseudo-record per message (RFC 6891 §6.1.1); got {opts}"
            )));
        }
        let qdcount: u16 = match spec.fields.get("qdcount") {
            Some(Value::Int(v)) => *v as u16,
            _ if af => qname.is_some().into(),
            _ => 0,
        };
        let count_or = |key: &str, crafted: &[CraftedRecord]| -> u16 {
            match spec.fields.get(key) {
                Some(Value::Int(v)) => *v as u16,
                _ if af => crafted.len().min(u16::MAX as usize) as u16,
                _ => 0,
            }
        };
        ctx.buf.put_u16(qdcount);
        ctx.buf.put_u16(count_or("ancount", &crafted[0]));
        ctx.buf.put_u16(count_or("nscount", &crafted[1]));
        ctx.buf.put_u16(count_or("arcount", &crafted[2]));

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
        // Tranche 20a-2: the crafted record bodies, in section order.
        for section in &crafted {
            for r in section.iter() {
                ctx.buf.extend_from_slice(&r.name);
                ctx.buf.put_u16(r.rtype);
                ctx.buf.put_u16(r.class);
                ctx.buf.put_u32(r.ttl);
                ctx.buf.put_u16(r.rdata.len() as u16);
                ctx.buf.extend_from_slice(&r.rdata);
            }
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
        // Tranche 11b: parse-time field spans (codec-side entries the
        // engine merge honors over the static layouts table).
        let mut spans: BTreeMap<Cow<'static, str>, FieldSpan> = BTreeMap::new();
        // The flags aggregate is SCATTERED (qr=bit15, aa=10, tc=9,
        // rd=8, ra=7, ad=5, cd=4 of one word): not one contiguous
        // window, so the aggregate itself carries `None` (use the
        // per-bit subpaths) and each subbit gets its real single-bit
        // window. Tranche 20a-1: ad/cd join; z (bit 6) renders too but
        // never crafts.
        let base = ctx.offset;
        spans.insert("flags".into(), FieldSpan::None);
        for (bit, shift) in [
            ("qr", 0u8),
            ("aa", 5),
            ("tc", 6),
            ("rd", 7),
            ("ra", 8),
            ("ad", 10),
            ("cd", 11),
        ] {
            spans.insert(
                format!("flags.{bit}").into(),
                FieldSpan::Bits {
                    container: base + 2..base + 4,
                    shift,
                    width: 1,
                },
            );
        }
        spans.insert(
            "flags.z".into(),
            FieldSpan::Bits {
                container: base + 2..base + 4,
                shift: 9,
                width: 1,
            },
        );
        let id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let word = u16::from_be_bytes([bytes[2], bytes[3]]);
        let opcode = (word >> 11) & 0x0F;
        let rcode = word & 0x0F;
        let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
        let ancount = u16::from_be_bytes([bytes[6], bytes[7]]);
        let nscount = u16::from_be_bytes([bytes[8], bytes[9]]);
        let arcount = u16::from_be_bytes([bytes[10], bytes[11]]);
        fields.insert("id".into(), Value::Int(id as u128));
        // Tranche 20a-1: a set z bit is a never-fatal anomaly (RFC 1035
        // §4.1.1 requires zero).
        fields.insert("flags.z".into(), Value::Bool(word & 0x0040 != 0));
        if word & 0x0040 != 0 {
            ctx.anomalies.push(Anomaly::new(
                "dns.flags.z",
                "z bit set (RFC 1035 §4.1.1 requires zero)".to_string(),
            ));
        }
        // Single-bit flags at word bits 15,10,9,8,7,5,4, in bit_names order.
        let mut names: Vec<Value> = Vec::new();
        if word & 0x8000 != 0 {
            names.push(Value::Str(Cow::Borrowed("qr")));
        }
        if word & 0x0400 != 0 {
            names.push(Value::Str(Cow::Borrowed("aa")));
        }
        if word & 0x0200 != 0 {
            names.push(Value::Str(Cow::Borrowed("tc")));
        }
        if word & 0x0100 != 0 {
            names.push(Value::Str(Cow::Borrowed("rd")));
        }
        if word & 0x0080 != 0 {
            names.push(Value::Str(Cow::Borrowed("ra")));
        }
        // Tranche 20a-1 (ad = bit 5, cd = bit 4).
        if word & 0x0020 != 0 {
            names.push(Value::Str(Cow::Borrowed("ad")));
        }
        if word & 0x0010 != 0 {
            names.push(Value::Str(Cow::Borrowed("cd")));
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
                    spans.insert(
                        format!("qd.{i}.name").into(),
                        name_span(base, cursor, q.name_used, q.name_region),
                    );
                    let at = base + cursor + q.name_used;
                    spans.insert(format!("qd.{i}.type").into(), FieldSpan::Bytes(at..at + 2));
                    spans.insert(
                        format!("qd.{i}.class").into(),
                        FieldSpan::Bytes(at + 2..at + 4),
                    );
                    fields.insert(format!("qd.{i}.name").into(), Value::Str(q.name.into()));
                    fields.insert(
                        format!("qd.{i}.type").into(),
                        Value::Str(render_type(q.qtype).into()),
                    );
                    fields.insert(
                        format!("qd.{i}.class").into(),
                        Value::Str(render_class(q.qclass).into()),
                    );
                    cursor = next;
                }
                Err(e) => {
                    ctx.anomalies
                        .push(Anomaly::new(format!("dns.qd.{i}.name"), e));
                    return partial(ctx, fields, spans, cursor);
                }
            }
        }
        // Answer / authority / additional sections.
        for (section, count) in [("an", ancount), ("ns", nscount), ("ar", arcount)] {
            for i in 0..count {
                match record_at(bytes, cursor) {
                    Ok((r, next)) => {
                        spans.insert(
                            format!("{section}.{i}.name").into(),
                            name_span(base, cursor, r.name_used, r.name_region),
                        );
                        let at = base + cursor + r.name_used;
                        spans.insert(
                            format!("{section}.{i}.type").into(),
                            FieldSpan::Bytes(at..at + 2),
                        );
                        spans.insert(
                            format!("{section}.{i}.class").into(),
                            FieldSpan::Bytes(at + 2..at + 4),
                        );
                        spans.insert(
                            format!("{section}.{i}.ttl").into(),
                            FieldSpan::Bytes(at + 4..at + 8),
                        );
                        spans.insert(
                            format!("{section}.{i}.rdata").into(),
                            FieldSpan::Bytes(base + r.rdata_at..base + r.rdata_at + r.rdata.len()),
                        );
                        fields.insert(
                            format!("{section}.{i}.name").into(),
                            Value::Str(r.name.clone().into()),
                        );
                        fields.insert(
                            format!("{section}.{i}.type").into(),
                            Value::Str(render_type(r.rtype).into()),
                        );
                        fields.insert(
                            format!("{section}.{i}.class").into(),
                            Value::Str(render_class(r.rclass).into()),
                        );
                        fields.insert(
                            format!("{section}.{i}.ttl").into(),
                            Value::Int(r.ttl as u128),
                        );
                        fields.insert(
                            format!("{section}.{i}.rdata").into(),
                            typed_rdata(r.rtype, &r.rdata, bytes, r.rdata_at, ctx, section, i),
                        );
                        // Tranche 20a-1: the OPT pseudo-record unpacks its
                        // class/ttl (udp size / ext-rcode / version / DO / z)
                        // and walks its option TLVs (RFC 6891 §6.1).
                        if r.rtype == TYPE_OPT {
                            opt_subfields(
                                &mut fields,
                                &mut spans,
                                &mut ctx.anomalies,
                                section,
                                i,
                                &r,
                                at,
                                base,
                            );
                        } else {
                            // Tranche 20a-2: typed rdata subfields under
                            // `{section}.{i}.{type}.*` (the rdata stays raw
                            // bytes above — the wire truth).
                            typed_subfields(
                                &mut fields,
                                &mut spans,
                                &mut ctx.anomalies,
                                section,
                                i,
                                r.rtype,
                                &r.rdata,
                                bytes,
                                r.rdata_at,
                                base,
                            );
                        }
                        cursor = next;
                    }
                    Err(e) => {
                        ctx.anomalies
                            .push(Anomaly::new(format!("dns.{section}.{i}.name"), e));
                        return partial(ctx, fields, spans, cursor);
                    }
                }
            }
        }

        let view = LayerView {
            kind: "dns",
            span: ctx.offset..ctx.offset + bytes.len(),
            field_spans: spans,
            fields,
        };
        ReadOutcome::Layer(view, Some(Next::Payload))
    }

    /// Tranche 11b fixed layouts: the 12-byte header. The scattered
    /// `flags` aggregate and all record-section fields are codec-side
    /// (parse-time spans). The counts are deliberately **not**
    /// `Derived` targets: section-count recomputation is ill-defined
    /// under desync (the dissector trusts the count), and the
    /// add-a-record workflow patches the count explicitly.
    fn layouts(&self) -> &'static [(&'static str, Layout)] {
        &[
            ("id", Layout::Bytes { at: 0, len: 2 }),
            (
                "opcode",
                Layout::Bits {
                    at: 2,
                    shift: 1,
                    width: 4,
                },
            ),
            (
                "rcode",
                Layout::Bits {
                    at: 2,
                    shift: 12,
                    width: 4,
                },
            ),
            ("qdcount", Layout::Bytes { at: 4, len: 2 }),
            ("ancount", Layout::Bytes { at: 6, len: 2 }),
            ("nscount", Layout::Bytes { at: 8, len: 2 }),
            ("arcount", Layout::Bytes { at: 10, len: 2 }),
        ]
    }

    /// Tranche 13a: names — compressed or not — re-encode at their
    /// recorded region. For a pointer-resolved name the region is the
    /// **pointer target** (see [`name_span`]): a same-width wire-name
    /// rewrite lands *at the shared target*, so every alias through
    /// that pointer sees the change (the alias-safety contract).
    /// Length-changing rewrites ride `Insert`/`Delete` at the caller
    /// (the T11b-β policy, unchanged).
    fn reencode(
        &self,
        field: &str,
        value: &[u8],
        region: std::ops::Range<usize>,
    ) -> Option<Result<Vec<u8>, String>> {
        if !field.ends_with(".name") {
            return None;
        }
        if value.len() != region.len() {
            return Some(Err(format!(
                "wire name wants {} bytes (got {}); length changes ride Insert/Delete",
                region.len(),
                value.len()
            )));
        }
        // The replacement must be a complete, uncompressed wire name
        // (labels + root byte) consuming the region exactly — a
        // malformed label run at a shared pointer target would corrupt
        // every alias, so validation is pointed, never assumed.
        match decode_name(value, 0) {
            Ok((_, used, false, None)) if used == value.len() => Some(Ok(value.to_vec())),
            _ => Some(Err(
                "value is not a complete uncompressed wire name".to_string()
            )),
        }
    }
}

/// The span of one name field (tranche 13a): uncompressed names carry
/// their real `Bytes` extent from the record start; pointer-resolved
/// names carry a [`FieldSpan::ReEncode`] over the **final pointer
/// target**'s extent, so a patch rewrites the shared target in place
/// (same width) instead of the 2-byte pointer.
fn name_span(
    base: usize,
    cursor: usize,
    name_used: usize,
    name_region: Option<(usize, usize)>,
) -> FieldSpan {
    match name_region {
        None => FieldSpan::Bytes(base + cursor..base + cursor + name_used),
        Some((target, extent)) => FieldSpan::ReEncode(base + target..base + target + extent),
    }
}

/// Build a partial (never-fatal) layer view for `bytes[..consumed]`.
fn partial(
    ctx: &mut DecodeCtx<'_>,
    fields: BTreeMap<Cow<'static, str>, Value>,
    spans: BTreeMap<Cow<'static, str>, FieldSpan>,
    consumed: usize,
) -> ReadOutcome {
    ReadOutcome::Layer(
        LayerView {
            kind: "dns",
            span: ctx.offset..ctx.offset + consumed,
            field_spans: spans,
            fields,
        },
        Some(Next::Payload),
    )
}

/// One parsed question, carrying the span bookkeeping (tranche 11b /
/// 13a).
struct Question {
    name: String,
    qtype: u16,
    qclass: u16,
    /// Name wire extent from the record start.
    name_used: usize,
    /// Pointer-resolved name (tranche 13a): `(target, extent)` — the
    /// message-relative offset of the final pointer target and its
    /// full wire extent there. `None` = uncompressed (a real span).
    name_region: Option<(usize, usize)>,
}

/// Parse the question at `offset` + next offset.
fn question_at(bytes: &[u8], offset: usize) -> Result<(Question, usize), String> {
    let (name, used, _compressed, target) = decode_name(bytes, offset)?;
    let name_region = name_region(bytes, target)?;
    let at = offset + used;
    if at + 4 > bytes.len() {
        return Err("truncated question (need 4 bytes for type/class)".to_string());
    }
    let qtype = u16::from_be_bytes([bytes[at], bytes[at + 1]]);
    let qclass = u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]);
    Ok((
        Question {
            name,
            qtype,
            qclass,
            name_used: used,
            name_region,
        },
        at + 4,
    ))
}

/// Resolve a compression-pointer target (tranche 13a) to
/// `(target, wire extent at the target)` — the target of the *final*
/// jump, so the segment there terminates without further pointers and
/// `decode_name` yields its full extent.
fn name_region(bytes: &[u8], target: Option<usize>) -> Result<Option<(usize, usize)>, String> {
    match target {
        None => Ok(None),
        Some(t) => {
            let (_, used, _c, next) = decode_name(bytes, t)?;
            // `t` is the FINAL target by the decode_name contract: the
            // walk from it never jumps again, so `next` is None and
            // `used` is the full extent. (A Some here would contradict
            // the contract; keep the walk honest anyway.)
            debug_assert_eq!(next, None, "final pointer target jumped again");
            Ok(Some((t, used)))
        }
    }
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
    /// Name wire extent from the record start (tranche 11b).
    name_used: usize,
    /// Pointer-resolved name (tranche 13a): `(target, extent)`;
    /// `None` = uncompressed.
    name_region: Option<(usize, usize)>,
}

/// Parse one RR at `offset`: owner, type, class, ttl, rdlength, rdata.
fn record_at(bytes: &[u8], offset: usize) -> Result<(Record, usize), String> {
    let (name, used, _compressed, target) = decode_name(bytes, offset)?;
    let name_region = name_region(bytes, target)?;
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
            name_used: used,
            name_region,
        },
        rdata_at + rdlen,
    ))
}

/// The typed-subfield walker (tranche 20a-1/20a-2): one record's rdata
/// cursor, inserting dynamic dissect-only paths under
/// `{section}.{i}.{…}` with their real spans. Never fatal: a truncated
/// or malformed shape pushes a never-fatal anomaly and leaves the
/// remainder of the walk unsaid (the rdata itself stays raw bytes —
/// the typed subfields are rendering, never the wire truth).
struct Walk<'a> {
    fields: &'a mut BTreeMap<Cow<'static, str>, Value>,
    spans: &'a mut BTreeMap<Cow<'static, str>, FieldSpan>,
    /// Non-fatal anomalies (the caller's `ctx.anomalies` — never fatal).
    anomalies: &'a mut Vec<Anomaly>,
    /// The dns-layer message (rdata name pointers are layer-relative).
    message: &'a [u8],
    prefix: String,
    /// dns-layer-relative offset of the rdata start.
    rdata_at: usize,
    /// absolute offset of the dns layer start (`base + …` is absolute).
    base: usize,
    rdata: &'a [u8],
    /// cursor within rdata.
    at: usize,
}

impl<'a> Walk<'a> {
    fn key(&self, name: &str) -> Cow<'static, str> {
        format!("{}.{}", self.prefix, name).into()
    }

    fn insert(&mut self, name: &str, v: Value, span: FieldSpan) {
        self.spans.insert(self.key(name), span);
        self.fields.insert(self.key(name), v);
    }

    /// Absolute range for an rdata-relative window.
    fn abs(&self, rel: usize, len: usize) -> std::ops::Range<usize> {
        self.base + self.rdata_at + rel..self.base + self.rdata_at + rel + len
    }

    /// BE int of `width` bytes at the cursor.
    fn int(&mut self, name: &str, width: usize) -> Option<u128> {
        let end = self.at + width;
        let chunk = self.rdata.get(self.at..end)?;
        let v = chunk.iter().fold(0u128, |a, b| (a << 8) | *b as u128);
        self.at = end;
        self.insert(
            name,
            Value::Int(v),
            FieldSpan::Bytes(self.abs(end - width, width)),
        );
        Some(v)
    }

    /// A domain name at the cursor (compression pointers resolved).
    fn name(&mut self, name: &str) -> Option<String> {
        let rel = self.at;
        let (n, used, _c, _t) = decode_name(self.message, self.rdata_at + rel).ok()?;
        self.at = rel + used;
        let span = FieldSpan::Bytes(self.abs(rel, used));
        self.insert(name, Value::Str(n.clone().into()), span);
        Some(n)
    }

    /// A record TYPE at the cursor (RRSIG.covered, RFC 4034 §3.1.1),
    /// rendered by name.
    fn rtype_field(&mut self, name: &str, width: usize) -> Option<()> {
        let end = self.at + width;
        let chunk = self.rdata.get(self.at..end)?;
        let v = chunk.iter().fold(0u16, |a, b| (a << 8) | *b as u16);
        self.at = end;
        let span = FieldSpan::Bytes(self.abs(end - width, width));
        self.insert(name, Value::Str(render_type(v).into()), span);
        Some(())
    }

    /// One character-string (RFC 1035 §3.3, length-prefixed), rendered
    /// lossily and returned so aggregate walks (TXT strings, alpn) can
    /// collect it without keeping the dummy key.
    fn charstr(&mut self, dummy: &str) -> Option<String> {
        let len = *self.rdata.get(self.at)? as usize;
        let end = self.at + 1 + len;
        let chunk = self.rdata.get(self.at + 1..end)?;
        let s = String::from_utf8_lossy(chunk).into_owned();
        let span = FieldSpan::Bytes(self.abs(self.at, 1 + len));
        self.at = end;
        self.spans.insert(self.key(dummy), span);
        self.fields
            .insert(self.key(dummy), Value::Str(s.clone().into()));
        Some(s)
    }

    /// Drop a dummy key the aggregate walks inserted.
    fn drop_key(&mut self, name: &str) {
        let k = self.key(name);
        self.fields.remove(&k);
        self.spans.remove(&k);
    }

    /// The remainder of the rdata, as raw bytes.
    fn rest(&mut self, name: &str) -> Option<()> {
        let rel = self.at;
        let chunk = self.rdata.get(rel..)?;
        self.at = self.rdata.len();
        self.insert(
            name,
            Value::Bytes(Bytes::copy_from_slice(chunk)),
            FieldSpan::Bytes(self.abs(rel, chunk.len())),
        );
        Some(())
    }

    fn anomaly(&mut self, what: &str) {
        // The dns. prefix matches the record-section error paths in
        // `read` (the corpus goldens pin `dns.an.0.name` shapes).
        self.anomalies.push(Anomaly::new(
            format!("dns.{}.{}", self.prefix, what),
            format!("bad {what} rdata (truncated or malformed)"),
        ));
    }
}

/// Typed rdata subfields per record type (tranche 20a-2): the full
/// alias-table completion of the tranche-3 freeze — MX/SOA/SRV/TXT
/// rdata used to stay raw bytes with nothing rendered; now every
/// common record type walks its fields under
/// `{section}.{i}.{type}.*`. Read-side structural rendering only:
/// **no DNSSEC validation ever** (chain validation is a recorded
/// won't-do; DS/DNSKEY/RRSIG/NSEC render their shapes).
#[allow(clippy::too_many_arguments)]
fn typed_subfields(
    fields: &mut BTreeMap<Cow<'static, str>, Value>,
    spans: &mut BTreeMap<Cow<'static, str>, FieldSpan>,
    anomalies: &mut Vec<Anomaly>,
    section: &str,
    index: u16,
    rtype: u16,
    rdata: &Bytes,
    message: &[u8],
    rdata_at: usize,
    base: usize,
) {
    let type_name = render_type(rtype);
    let mut w = Walk {
        fields,
        spans,
        anomalies,
        message,
        prefix: format!("{section}.{index}"),
        rdata_at,
        base,
        rdata,
        at: 0,
    };
    /// One typed step: a truncated/malformed shape pushes one
    /// never-fatal anomaly (keyed at the record's type path) and ends
    /// the walk — the rdata stays raw above.
    macro_rules! step {
        ($e:expr) => {
            if $e.is_none() {
                w.anomaly(&type_name);
                return;
            }
        };
    }
    match rtype {
        crate::types::TYPE_MX => {
            step!(w.int("mx.preference", 2));
            step!(w.name("mx.exchange"));
        }
        crate::types::TYPE_SOA => {
            step!(w.name("soa.mname"));
            step!(w.name("soa.rname"));
            step!(w.int("soa.serial", 4));
            step!(w.int("soa.refresh", 4));
            step!(w.int("soa.retry", 4));
            step!(w.int("soa.expire", 4));
            step!(w.int("soa.minimum", 4));
        }
        crate::types::TYPE_SRV => {
            step!(w.int("srv.priority", 2));
            step!(w.int("srv.weight", 2));
            step!(w.int("srv.port", 2));
            step!(w.name("srv.target"));
        }
        crate::types::TYPE_TXT => {
            // Character-strings to the end of the rdata (RFC 1035 §3.3.14).
            let mut strings: Vec<Value> = Vec::new();
            while w.at < w.rdata.len() {
                match w.charstr("txt.dummy") {
                    Some(s) => {
                        w.drop_key("txt.dummy");
                        strings.push(Value::Str(s.into()));
                    }
                    None => {
                        w.anomaly("txt");
                        return;
                    }
                }
            }
            w.insert(
                "txt.strings",
                Value::List(strings),
                FieldSpan::Bytes(w.abs(0, w.rdata.len())),
            );
        }
        crate::types::TYPE_CAA => {
            step!(w.int("caa.flags", 1));
            step!(w.charstr("caa.tag"));
            step!(w.rest("caa.value"));
        }
        crate::types::TYPE_DNAME => {
            step!(w.name("dname.target"));
        }
        crate::types::TYPE_DS => {
            step!(w.int("ds.key_tag", 2));
            step!(w.int("ds.algorithm", 1));
            step!(w.int("ds.digest_type", 1));
            step!(w.rest("ds.digest"));
        }
        crate::types::TYPE_DNSKEY => {
            step!(w.int("dnskey.flags", 2));
            step!(w.int("dnskey.protocol", 1));
            step!(w.int("dnskey.algorithm", 1));
            step!(w.rest("dnskey.key"));
        }
        crate::types::TYPE_RRSIG => {
            // RFC 4034 §3.1: covered is a TYPE (not a name), then
            // algorithm, labels, orig ttl, expiration, inception,
            // key tag, signer name, signature.
            step!(w.rtype_field("rrsig.covered", 2));
            step!(w.int("rrsig.algorithm", 1));
            step!(w.int("rrsig.labels", 1));
            step!(w.int("rrsig.orig_ttl", 4));
            step!(w.int("rrsig.expiration", 4));
            step!(w.int("rrsig.inception", 4));
            step!(w.int("rrsig.key_tag", 2));
            step!(w.name("rrsig.signer"));
            step!(w.rest("rrsig.sig"));
        }
        crate::types::TYPE_NSEC => {
            step!(w.name("nsec.next"));
            // Type bitmap (RFC 4034 §4.1.2): window blocks.
            let mut types: Vec<Value> = Vec::new();
            while w.at < w.rdata.len() {
                let (Some(win), Some(bl)) =
                    (w.rdata.get(w.at).copied(), w.rdata.get(w.at + 1).copied())
                else {
                    w.anomaly("nsec");
                    return;
                };
                let end = w.at + 2 + bl as usize;
                let Some(bitmap) = w.rdata.get(w.at + 2..end) else {
                    w.anomaly("nsec");
                    return;
                };
                for (bi, byte) in bitmap.iter().enumerate() {
                    for bit in (0..8).rev() {
                        if byte & (1 << bit) != 0 {
                            let t = (win as u16) * 256 + (bi * 8 + (7 - bit)) as u16;
                            types.push(Value::Int(t as u128));
                        }
                    }
                }
                w.at = end;
            }
            w.insert(
                "nsec.types",
                Value::List(types),
                FieldSpan::Bytes(w.abs(0, w.rdata.len())),
            );
        }
        crate::types::TYPE_TLSA => {
            step!(w.int("tlsa.usage", 1));
            step!(w.int("tlsa.selector", 1));
            step!(w.int("tlsa.matching", 1));
            step!(w.rest("tlsa.data"));
        }
        crate::types::TYPE_SSHFP => {
            step!(w.int("sshfp.algorithm", 1));
            step!(w.int("sshfp.fptype", 1));
            step!(w.rest("sshfp.fingerprint"));
        }
        crate::types::TYPE_HINFO => {
            step!(w.charstr("hinfo.cpu"));
            step!(w.charstr("hinfo.os"));
        }
        crate::types::TYPE_NAPTR => {
            step!(w.int("naptr.order", 2));
            step!(w.int("naptr.pref", 2));
            step!(w.charstr("naptr.flags"));
            step!(w.charstr("naptr.service"));
            step!(w.charstr("naptr.regexp"));
            step!(w.name("naptr.replacement"));
        }
        crate::types::TYPE_SVCB | crate::types::TYPE_HTTPS => {
            step!(w.int("svcb.priority", 2));
            step!(w.name("svcb.target"));
            // Alias mode (priority 0): no SvcParams allowed (RFC 9460
            // §2.2) — a pointed never-fatal anomaly, the raw value stays.
            if w.at >= w.rdata.len() {
                return;
            }
            if w.fields.get(&w.key("svcb.priority")) == Some(&Value::Int(0)) {
                w.anomaly("svcb");
                return;
            }
            let mut m = 0usize;
            while w.at < w.rdata.len() {
                let Some(key) = w
                    .rdata
                    .get(w.at..w.at + 2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                else {
                    w.anomaly("svcb");
                    return;
                };
                let Some(vlen) = w
                    .rdata
                    .get(w.at + 2..w.at + 4)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                else {
                    w.anomaly("svcb");
                    return;
                };
                let vend = w.at + 4 + vlen as usize;
                let Some(value) = w.rdata.get(w.at + 4..vend) else {
                    w.anomaly("svcb");
                    return;
                };
                let param_span = FieldSpan::Bytes(w.abs(w.at + 4, value.len()));
                w.spans.insert(
                    format!("{}.svcb.{m}.key", w.prefix).into(),
                    FieldSpan::Bytes(w.abs(w.at, 2)),
                );
                w.fields.insert(
                    format!("{}.svcb.{m}.key", w.prefix).into(),
                    Value::Int(key as u128),
                );
                w.spans.insert(
                    format!("{}.svcb.{m}.value", w.prefix).into(),
                    param_span.clone(),
                );
                w.fields.insert(
                    format!("{}.svcb.{m}.value", w.prefix).into(),
                    Value::Bytes(Bytes::copy_from_slice(value)),
                );
                // Typed param subsets (RFC 9460 §7.4 shapes), walked over
                // the param value directly (one cursor, no nested borrows).
                match key {
                    0 => {
                        // alpn: length-prefixed protocol ids.
                        let mut names: Vec<Value> = Vec::new();
                        let mut cat = 0usize;
                        while cat < value.len() {
                            let l = value[cat] as usize;
                            let end = cat + 1 + l;
                            let Some(chunk) = value.get(cat + 1..end) else {
                                break;
                            };
                            names.push(Value::Str(
                                String::from_utf8_lossy(chunk).into_owned().into(),
                            ));
                            cat = end;
                        }
                        if !names.is_empty() {
                            w.insert(&format!("svcb.{m}.alpn"), Value::List(names), param_span);
                        }
                    }
                    2 => {
                        // port: exactly 2 bytes.
                        if let Some(p) = value.get(0..2).map(|c| u16::from_be_bytes([c[0], c[1]])) {
                            w.insert(&format!("svcb.{m}.port"), Value::Int(p as u128), param_span);
                        }
                    }
                    3 => {
                        // ipv4hint: 4-byte addresses.
                        let addrs: Vec<Value> = value
                            .chunks(4)
                            .filter_map(|c| <[u8; 4]>::try_from(c).ok())
                            .map(std::net::Ipv4Addr::from)
                            .map(Value::Ipv4)
                            .collect();
                        if !addrs.is_empty() {
                            w.insert(
                                &format!("svcb.{m}.ipv4hint"),
                                Value::List(addrs),
                                param_span,
                            );
                        }
                    }
                    6 => {
                        // ipv6hint: 16-byte addresses.
                        let addrs: Vec<Value> = value
                            .chunks(16)
                            .filter_map(|c| <[u8; 16]>::try_from(c).ok())
                            .map(std::net::Ipv6Addr::from)
                            .map(Value::Ipv6)
                            .collect();
                        if !addrs.is_empty() {
                            w.insert(
                                &format!("svcb.{m}.ipv6hint"),
                                Value::List(addrs),
                                param_span,
                            );
                        }
                    }
                    _ => {}
                }
                m += 1;
                w.at = vend;
            }
        }
        _ => {}
    }
}

/// Typed OPT pseudo-record (tranche 20a-1): the class field IS the udp
/// payload size and the ttl carries ext-rcode/version/DO (RFC 6891
/// §6.1) — both unpack under `ar.N.*` — and the rdata option TLVs walk
/// as `ar.N.opt.M.*` records (the dhcp `opt.N.*` pattern).
#[allow(clippy::too_many_arguments)]
fn opt_subfields(
    fields: &mut BTreeMap<Cow<'static, str>, Value>,
    spans: &mut BTreeMap<Cow<'static, str>, FieldSpan>,
    anomalies: &mut Vec<Anomaly>,
    section: &str,
    index: u16,
    r: &Record,
    at: usize,
    base: usize,
) {
    let prefix = format!("{section}.{index}");
    let put = |fields: &mut BTreeMap<Cow<'static, str>, Value>,
               spans: &mut BTreeMap<Cow<'static, str>, FieldSpan>,
               name: &str,
               v: Value,
               span: FieldSpan| {
        let key: Cow<'static, str> = format!("{prefix}.{name}").into();
        spans.insert(key.clone(), span);
        fields.insert(key, v);
    };
    // class = udp payload size (the same wire bytes, read again).
    put(
        fields,
        spans,
        "udp_size",
        Value::Int(r.rclass as u128),
        FieldSpan::Bytes(at + 2..at + 4),
    );
    // ttl: ext-rcode (bits 31..24), version (23..16), DO (15), z (14..0).
    let ttl = r.ttl;
    put(
        fields,
        spans,
        "ext_rcode",
        Value::Int((ttl >> 24) as u128),
        FieldSpan::Bits {
            container: at + 4..at + 8,
            shift: 0,
            width: 8,
        },
    );
    put(
        fields,
        spans,
        "version",
        Value::Int(((ttl >> 16) & 0xFF) as u128),
        FieldSpan::Bits {
            container: at + 4..at + 8,
            shift: 8,
            width: 8,
        },
    );
    put(
        fields,
        spans,
        "do",
        Value::Bool(ttl & 0x8000 != 0),
        FieldSpan::Bits {
            container: at + 4..at + 8,
            shift: 16,
            width: 1,
        },
    );
    put(
        fields,
        spans,
        "z",
        Value::Int((ttl & 0x7FFF) as u128),
        FieldSpan::Bits {
            container: at + 4..at + 8,
            shift: 17,
            width: 15,
        },
    );
    // Option TLVs (RFC 6891 §6.1.2): code(2) len(2) value.
    let rdata = &r.rdata;
    let mut m = 0usize;
    let mut cur = 0usize;
    while cur < rdata.len() {
        let Some(code) = rdata
            .get(cur..cur + 2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
        else {
            anomalies.push(Anomaly::new(
                format!("{prefix}.opt.{m}.code"),
                "truncated EDNS option header".to_string(),
            ));
            return;
        };
        let Some(vlen) = rdata
            .get(cur + 2..cur + 4)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
        else {
            anomalies.push(Anomaly::new(
                format!("{prefix}.opt.{m}.len"),
                "truncated EDNS option length".to_string(),
            ));
            return;
        };
        let vend = cur + 4 + vlen as usize;
        let Some(value) = rdata.get(cur + 4..vend) else {
            anomalies.push(Anomaly::new(
                format!("{prefix}.opt.{m}.value"),
                format!("EDNS option overruns the rdata (need {vlen})"),
            ));
            return;
        };
        let value_span = FieldSpan::Bytes(base + r.rdata_at + cur + 4..base + r.rdata_at + vend);
        put(
            fields,
            spans,
            &format!("opt.{m}.code"),
            Value::Int(code as u128),
            FieldSpan::Bytes(base + r.rdata_at + cur..base + r.rdata_at + cur + 2),
        );
        put(
            fields,
            spans,
            &format!("opt.{m}.len"),
            Value::Int(vlen as u128),
            FieldSpan::Bytes(base + r.rdata_at + cur + 2..base + r.rdata_at + cur + 4),
        );
        put(
            fields,
            spans,
            &format!("opt.{m}.value"),
            Value::Bytes(Bytes::copy_from_slice(value)),
            value_span.clone(),
        );
        // Typed subsets (the dhcp `opt` precedent): ECS (RFC 7871,
        // key 8) renders family/prefix/scope/addr; COOKIE (RFC 7873,
        // key 10) splits client/server.
        match code {
            8 => {
                let fam = value.get(0..2).map(|c| u16::from_be_bytes([c[0], c[1]]));
                let src = value.get(2).copied();
                let scope = value.get(3).copied();
                if let (Some(fam), Some(src), Some(scope)) = (fam, src, scope) {
                    put(
                        fields,
                        spans,
                        &format!("opt.{m}.ecs_family"),
                        Value::Int(fam as u128),
                        value_span.clone(),
                    );
                    put(
                        fields,
                        spans,
                        &format!("opt.{m}.ecs_prefix"),
                        Value::Int(src as u128),
                        value_span.clone(),
                    );
                    put(
                        fields,
                        spans,
                        &format!("opt.{m}.ecs_scope"),
                        Value::Int(scope as u128),
                        value_span.clone(),
                    );
                    let keep = (src as usize).div_ceil(8);
                    if let Some(addr) = value.get(4..4 + keep) {
                        let v = match (fam, addr.len()) {
                            (1, 4) => Value::Ipv4(std::net::Ipv4Addr::new(
                                addr[0], addr[1], addr[2], addr[3],
                            )),
                            (2, 16) => {
                                let mut o = [0u8; 16];
                                o.copy_from_slice(addr);
                                Value::Ipv6(std::net::Ipv6Addr::from(o))
                            }
                            _ => Value::Bytes(Bytes::copy_from_slice(addr)),
                        };
                        put(
                            fields,
                            spans,
                            &format!("opt.{m}.ecs_addr"),
                            v,
                            value_span.clone(),
                        );
                    }
                }
            }
            10 => {
                // COOKIE: 8-byte client [+ server, to the value's end].
                if let Some(c) = value.get(0..8) {
                    put(
                        fields,
                        spans,
                        &format!("opt.{m}.cookie_client"),
                        Value::Bytes(Bytes::copy_from_slice(c)),
                        value_span.clone(),
                    );
                }
                if let Some(s) = value.get(8..value.len().min(16)) {
                    put(
                        fields,
                        spans,
                        &format!("opt.{m}.cookie_server"),
                        Value::Bytes(Bytes::copy_from_slice(s)),
                        value_span,
                    );
                }
            }
            _ => {}
        }
        cur = vend;
        m += 1;
    }
}

/// Typed rdata per the tranche-3 freeze: A → ipv4, CNAME/NS/PTR →
/// resolved name, everything else raw bytes. Bad A rdata degrades to
/// raw bytes + anomaly (never fatal). Tranche 20a-2: the typed
/// *subfields* of the other record types walk separately
/// ([`typed_subfields`]) — the rdata value itself stays the wire truth.
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
                Ok((name, _, _, _)) => Value::Str(name.into()),
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
    /// exact). Tranche 20a-2: one record per section (an/ns/ar) rides
    /// the settable index paths, its rdata generated VALID per type
    /// (MX/TXT/SOA/SRV/CAA — the rdata-stays-raw set) so the
    /// differential's anomaly-free assertion holds and the typed
    /// subfield walks stay honest.
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
        let rtype = proptest::sample::select(vec!["MX", "TXT", "SOA", "SRV", "CAA"]);
        (
            any::<u16>(),
            any::<u8>(),
            (0u8..=15),
            (0u8..=15),
            name.clone(),
            qtype,
            qclass.clone(),
            rtype,
            name,
            qclass,
            any::<u32>(),
            any::<u8>(),
        )
            .prop_map(
                |(
                    id,
                    mask,
                    opcode,
                    rcode,
                    qname,
                    qtype,
                    qclass,
                    rtype,
                    rname,
                    rclass,
                    ttl,
                    flags_u8,
                )| {
                    let mut fields = std::collections::BTreeMap::new();
                    fields.insert("id".into(), Value::Int(id as u128));
                    fields.insert("flags".into(), Value::Int(mask as u128));
                    // G1 sweep: opcode/rcode are real 4-bit wire windows
                    // (RFC 1035 §4.1.1) — never sampled before.
                    fields.insert("opcode".into(), Value::Int(opcode as u128));
                    fields.insert("rcode".into(), Value::Int(rcode as u128));
                    fields.insert("qd.0.name".into(), Value::Str(qname.into()));
                    fields.insert(
                        "qd.0.type".into(),
                        Value::Str(render_type(parse_type(qtype).unwrap()).into()),
                    );
                    fields.insert(
                        "qd.0.class".into(),
                        Value::Str(render_class(parse_class(qclass).unwrap()).into()),
                    );
                    // Tranche 20a-2: one settable record per section, the
                    // rdata VALID per its type (the walk types it).
                    let rdata = record_rdata(rtype, &rname, flags_u8);
                    for section in ["an", "ns", "ar"] {
                        let p = format!("{section}.0.");
                        fields.insert(format!("{p}name").into(), Value::Str(rname.clone().into()));
                        fields.insert(
                            format!("{p}type").into(),
                            Value::Str(render_type(parse_type(rtype).unwrap()).into()),
                        );
                        fields.insert(
                            format!("{p}class").into(),
                            Value::Str(render_class(parse_class(rclass).unwrap()).into()),
                        );
                        fields.insert(format!("{p}ttl").into(), Value::Int(ttl as u128));
                        fields.insert(
                            format!("{p}rdata").into(),
                            Value::Bytes(bytes::Bytes::copy_from_slice(&rdata)),
                        );
                    }
                    LayerSpec::with_fields("dns", fields)
                },
            )
            .boxed()
    }

    /// Valid rdata for the strategy's record-type pool (the
    /// rdata-stays-raw set): the walks type these without anomalies.
    fn record_rdata(rtype: &str, name: &str, flags_u8: u8) -> Vec<u8> {
        fn wire(n: &str, out: &mut Vec<u8>) {
            crate::name::encode_name(n, out).expect("strategy names encode");
        }
        match rtype {
            "MX" => {
                let mut out = Vec::new();
                out.extend_from_slice(&[0x00, flags_u8]); // preference
                wire(name, &mut out);
                out
            }
            "TXT" => {
                let mut out = Vec::new();
                let tag = format!("txt-{}", flags_u8);
                out.push(tag.len() as u8);
                out.extend_from_slice(tag.as_bytes());
                out
            }
            "SOA" => {
                let mut out = Vec::new();
                wire(name, &mut out);
                wire(name, &mut out);
                for v in [flags_u8 as u32, 7200, 3600, 1209600, 3600u32] {
                    out.extend_from_slice(&v.to_be_bytes());
                }
                out
            }
            "SRV" => {
                let mut out = Vec::new();
                // priority, weight, port (each u16), then target.
                out.extend_from_slice(&[0, flags_u8, 0, 0, 0x00, 0x50]);
                wire(name, &mut out);
                out
            }
            // CAA: flags, tag ("issue"), value.
            _ => {
                let mut out = vec![flags_u8, 0x05];
                out.extend_from_slice(b"issue");
                out.extend_from_slice(b"example.net");
                out
            }
        }
    }
}

#[cfg(test)]
mod tests {
    /// Schema invariant (const-eval pass): no duplicate field names in
    /// any table. `field_names_unique` is a const fn, but the tables are
    /// statics (`Bytes` interior mutability blocks const eval), so the
    /// proof runs here instead of in a `const _`.
    #[test]
    fn schema_field_names_unique() {
        assert!(wrex_core::schema::field_names_unique(super::SCHEMA.fields));
        for r in super::SCHEMA.records.iter() {
            assert!(wrex_core::schema::field_names_unique(r.fields));
        }
    }

    /// Schema invariant (const-eval pass): no duplicate field names in
    /// any table — `field_names_unique` is a const fn, but the tables
    /// are statics (Bytes interior mutability blocks const eval), so
    /// the proof runs here instead.
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
                "qd.0.name" | "qd.0.type" | "qd.0.class" => Value::Str((*v).to_string().into()),
                k if k.starts_with("flags.") => {
                    Value::Bool(v.parse::<bool>().map_err(|_| ()).unwrap_or(true))
                }
                _ => Value::Int(v.parse::<u128>().unwrap()),
            };
            map.insert(Cow::Owned(k.to_string()), value);
        }
        LayerSpec::with_fields("dns", map)
    }

    /// ADR 3: udp is a real parent dep, so this registers the actual
    /// udp codec through the `register()` closure and dissects a
    /// crafted udp(53)→dns datagram end to end — the string dispatch
    /// table can no longer drift from the kinds it names (no stand-in;
    /// the udp crate's dispatch-out tests still stub dns by design).
    #[test]
    fn udp_dispatches_into_dns_with_real_codecs() {
        let mut r = wrex_core::Registry::empty();
        register(&mut r);
        let mut uf = std::collections::BTreeMap::new();
        uf.insert("sport".into(), wrex_core::Value::Int(40000));
        uf.insert("dport".into(), wrex_core::Value::Int(53));
        let spec = wrex_core::spec::PacketSpec::new(
            vec![
                wrex_core::spec::LayerSpec::with_fields(wrex_proto_udp::KIND, uf),
                spec(&[("qd.0.name", "example.com")]),
            ],
            None,
        );
        let enc = wrex_core::encode::encode(
            &r,
            &spec,
            &wrex_core::encode::EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        let p = wrex_core::dissect::dissect(&r, &enc.bytes, wrex_proto_udp::KIND);
        assert_eq!(
            p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
            vec![wrex_proto_udp::KIND, KIND],
            "udp port 53 must chain into the real dns codec"
        );
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
                Value::Str(Cow::Borrowed("qr")),
                Value::Str(Cow::Borrowed("rd")),
                Value::Str(Cow::Borrowed("ra")),
            ]
        ));
        assert_eq!(
            l.fields.get("qd.0.name"),
            Some(&Value::Str(Cow::Borrowed("example.com")))
        );
        assert_eq!(
            l.fields.get("qd.0.type"),
            Some(&Value::Str(Cow::Borrowed("A")))
        );
        assert_eq!(
            l.fields.get("an.0.name"),
            Some(&Value::Str(Cow::Borrowed("example.com")))
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
        assert_eq!(
            l.fields.get("ar.0.type"),
            Some(&Value::Str(Cow::Borrowed("OPT")))
        );
        assert!(matches!(l.fields.get("ar.0.rdata"), Some(Value::Bytes(_))));
    }

    #[test]
    fn header_len_reflects_question() {
        let s = spec(&[("qd.0.name", "example.com")]);
        assert_eq!(CODEC.header_len(&s).unwrap(), 12 + 13 + 4);
        assert_eq!(CODEC.header_len(&spec(&[])).unwrap(), 12);
    }

    // --- tranche 20a ---------------------------------------------------------

    /// A spec builder that speaks the full typed value grammar (the
    /// string-only [`spec`] helper predates settable records).
    fn spec_v(fields: Vec<(&str, Value)>) -> LayerSpec {
        let mut map = BTreeMap::new();
        for (k, v) in fields {
            map.insert(Cow::Owned(k.to_string()), v);
        }
        LayerSpec::with_fields("dns", map)
    }

    fn packet(layers: Vec<LayerSpec>) -> PacketSpec {
        PacketSpec::new(layers, None)
    }

    /// 20a-1: the EDNS0 sugar appends one typed OPT pseudo-record.
    #[test]
    fn edns_sugar_appends_typed_opt() {
        let s = spec_v(vec![
            ("id", Value::Int(7)),
            ("qd.0.name", Value::Str("example.com".into())),
            ("edns", Value::Int(1232)),
            ("edns_do", Value::Int(1)),
            (
                "edns_options",
                Value::Str("nsid:ab12, cookie:aabbccddeeff001122334455, ecs:192.168.0.0/24".into()),
            ),
        ]);
        let enc = encode(&registry(), &packet(vec![s]), &opts()).unwrap();
        // arcount autofilled to 1 (the sugar's OPT record).
        assert_eq!(u16::from_be_bytes([enc.bytes[10], enc.bytes[11]]), 1);
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "dns");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        let l = &p.layers[0];
        assert_eq!(l.fields.get("ar.0.type"), Some(&Value::Str("OPT".into())));
        assert_eq!(l.fields.get("ar.0.udp_size"), Some(&Value::Int(1232)));
        assert_eq!(l.fields.get("ar.0.do"), Some(&Value::Bool(true)));
        assert_eq!(l.fields.get("ar.0.ext_rcode"), Some(&Value::Int(0)));
        assert_eq!(l.fields.get("ar.0.version"), Some(&Value::Int(0)));
        assert_eq!(l.fields.get("ar.0.z"), Some(&Value::Int(0)));
        // NSID (code 3) → value bytes.
        assert_eq!(l.fields.get("ar.0.opt.0.code"), Some(&Value::Int(3)));
        assert_eq!(
            l.fields.get("ar.0.opt.0.value"),
            Some(&Value::Bytes(Bytes::from_static(&[0xab, 0x12])))
        );
        // COOKIE (code 10) → client/server split (RFC 7873).
        assert_eq!(l.fields.get("ar.0.opt.1.code"), Some(&Value::Int(10)));
        assert_eq!(
            l.fields.get("ar.0.opt.1.cookie_client"),
            Some(&Value::Bytes(Bytes::from_static(&[
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11
            ])))
        );
        assert_eq!(
            l.fields.get("ar.0.opt.1.cookie_server"),
            Some(&Value::Bytes(Bytes::from_static(&[0x22, 0x33, 0x44, 0x55])))
        );
        // ECS (code 8, RFC 7871): family 1, prefix 24, scope 0.
        assert_eq!(l.fields.get("ar.0.opt.2.code"), Some(&Value::Int(8)));
        assert_eq!(l.fields.get("ar.0.opt.2.ecs_family"), Some(&Value::Int(1)));
        assert_eq!(l.fields.get("ar.0.opt.2.ecs_prefix"), Some(&Value::Int(24)));
        assert_eq!(l.fields.get("ar.0.opt.2.ecs_scope"), Some(&Value::Int(0)));
        assert_eq!(
            l.fields.get("ar.0.opt.2.ecs_addr"),
            Some(&Value::Bytes(Bytes::from_static(&[192, 168, 0])))
        );
    }

    /// 20a-1: knobs without --dns-edns advertise the dig-style default size.
    #[test]
    fn edns_knobs_default_the_size() {
        let s = spec_v(vec![("edns_do", Value::Int(1))]);
        let enc = encode(&registry(), &packet(vec![s]), &opts()).unwrap();
        assert_eq!(u16::from_be_bytes([enc.bytes[10], enc.bytes[11]]), 1);
        // The OPT class field (= udp payload size) defaults to 4096.
        // (The sugar's OPT record is 11 wire bytes: root, type, class,
        // ttl, rdlen 0.)
        let n = enc.bytes.len();
        let class = u16::from_be_bytes([enc.bytes[n - 8], enc.bytes[n - 7]]);
        assert_eq!(class, 4096);
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "dns");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(
            p.layers[0].fields.get("ar.0.udp_size"),
            Some(&Value::Int(4096))
        );
        assert_eq!(p.layers[0].fields.get("ar.0.do"), Some(&Value::Bool(true)));
    }

    /// 20a-1: the edns options grammar rejects garbage pointedly.
    #[test]
    fn edns_options_grammar_errors() {
        for bad in [
            "bogus:zz",
            "raw:99999:ab",
            "ecs:not-an-ip/24",
            "ecs:1.2.3.4/99",
        ] {
            let s = spec_v(vec![
                ("edns", Value::Int(1232)),
                ("edns_options", Value::Str(bad.into())),
            ]);
            let e = encode(&registry(), &packet(vec![s]), &opts()).unwrap_err();
            assert!(!e.to_string().is_empty(), "{bad}");
        }
    }

    /// 20a-1: ad/cd join the header aggregate (RFC 1035 §4.1.1 bits
    /// 5/4); z stays render-only with a never-fatal anomaly.
    #[test]
    fn ad_cd_craft_and_z_anomaly() {
        // Craft: aggregate mask bits 1 (ad) and 0 (cd) — the 7-bit
        // MSB-first unit [qr,aa,tc,rd,ra,ad,cd].
        let s = spec_v(vec![("flags", Value::Int(0b011))]);
        let enc = encode(&registry(), &packet(vec![s]), &opts()).unwrap();
        let word = u16::from_be_bytes([enc.bytes[2], enc.bytes[3]]);
        assert_eq!(word & 0x0020, 0x0020, "ad at word bit 5");
        assert_eq!(word & 0x0010, 0x0010, "cd at word bit 4");
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "dns");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert!(matches!(
            p.layers[0].fields.get("flags"),
            Some(Value::List(items)) if items == &vec![
                Value::Str(Cow::Borrowed("ad")),
                Value::Str(Cow::Borrowed("cd")),
            ]
        ));
        // Dissect: a set z bit renders + never-fatal anomaly.
        let mut msg = vec![0u8; 12];
        msg[2] = 0x00;
        msg[3] = 0x40; // z set (word bit 6)
        let p = wrex_core::dissect::dissect(&registry(), &msg, "dns");
        assert_eq!(p.layers[0].fields.get("flags.z"), Some(&Value::Bool(true)));
        assert!(
            p.anomalies.iter().any(|a| a.path == "dns.flags.z"),
            "{:?}",
            p.anomalies
        );
    }

    /// 20a-2: settable answer records (the tranche-3 deferral) — craft
    /// through the index paths, counts autofill, typed subfields walk.
    #[test]
    fn settable_answer_records() {
        // An MX answer: pref 10, exchange mail.example.com (wire in rdata).
        let s = spec_v(vec![
            ("id", Value::Int(9)),
            ("qd.0.name", Value::Str("example.com".into())),
            ("an.0.name", Value::Str("example.com".into())),
            ("an.0.type", Value::Str("MX".into())),
            ("an.0.class", Value::Str("IN".into())),
            ("an.0.ttl", Value::Int(300)),
            (
                "an.0.rdata",
                Value::Bytes(
                    [&[0x00, 0x0A][..], b"\x04mail\x07example\x03com\x00"]
                        .concat()
                        .into(),
                ),
            ),
        ]);
        let enc = encode(&registry(), &packet(vec![s]), &opts()).unwrap();
        // qdcount 1, ancount 1 (autofilled), arcount 0.
        assert_eq!(u16::from_be_bytes([enc.bytes[4], enc.bytes[5]]), 1);
        assert_eq!(u16::from_be_bytes([enc.bytes[6], enc.bytes[7]]), 1);
        assert_eq!(u16::from_be_bytes([enc.bytes[10], enc.bytes[11]]), 0);
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "dns");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        let l = &p.layers[0];
        assert_eq!(l.fields.get("an.0.type"), Some(&Value::Str("MX".into())));
        // 20a-2 typed subfields (the rdata itself stays raw bytes).
        assert_eq!(l.fields.get("an.0.mx.preference"), Some(&Value::Int(10)));
        assert_eq!(
            l.fields.get("an.0.mx.exchange"),
            Some(&Value::Str("mail.example.com".into()))
        );
        assert!(matches!(l.fields.get("an.0.rdata"), Some(Value::Bytes(_))));
    }

    /// 20a-2: a record without a type is a pointed gap; a non-root OPT
    /// owner is a pointed error (RFC 6891 §6.1.2); two OPTs rejected.
    #[test]
    fn record_craft_pointed_errors() {
        let e = encode(
            &registry(),
            &packet(vec![spec_v(vec![("an.0.name", Value::Str("x.io".into()))])]),
            &opts(),
        )
        .unwrap_err();
        assert!(
            matches!(e, wrex_core::EncodeError::Unfillable { ref field } if field == "dns.an.0.type"),
            "{e}"
        );
        let e = encode(
            &registry(),
            &packet(vec![spec_v(vec![
                ("ar.0.name", Value::Str("not.root".into())),
                ("ar.0.type", Value::Str("OPT".into())),
            ])]),
            &opts(),
        )
        .unwrap_err();
        assert!(e.to_string().contains("must be the root"), "{e}");
        // Sugar + explicit index-path OPT: two pseudo-records, pointed.
        let e = encode(
            &registry(),
            &packet(vec![spec_v(vec![
                ("edns", Value::Int(1232)),
                ("ar.0.type", Value::Str("OPT".into())),
            ])]),
            &opts(),
        )
        .unwrap_err();
        assert!(e.to_string().contains("at most one OPT"), "{e}");
    }

    /// 20a-2: the full typed-subfield table walks every common record
    /// type (hand-built reply, one record per index) — the per-type
    /// arms all exercised (the coverage gate rides the same units),
    /// including HTTPS/SVCB params and the DNSSEC read-side shapes.
    #[test]
    fn typed_subfield_walks() {
        // qd=0, an=10, ns=4, ar=1.
        let mut msg = vec![
            0x00, 0x01, 0x81, 0x80, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x04, 0x00, 0x01,
        ];
        // One record per section index; owners are literal names.
        let name: &[u8] = b"\x07example\x03com\x00";
        fn push_record(
            msg: &mut Vec<u8>,
            name: &[u8],
            rtype: u16,
            class: u16,
            ttl: u32,
            rdata: &[u8],
        ) {
            msg.extend_from_slice(name);
            msg.extend_from_slice(&rtype.to_be_bytes());
            msg.extend_from_slice(&class.to_be_bytes());
            msg.extend_from_slice(&ttl.to_be_bytes());
            msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            msg.extend_from_slice(rdata);
        }
        // an.0: SOA (mname, rname, serial, refresh, retry, expire, minimum)
        let soa_rec = b"\x02ns\x07example\x03com\x00\x05hostm\x07example\x03com\x00\
            \x00\x00\x00\x2A\x00\x00\x00\x64\x00\x00\x00\xC8\x00\x00\x01\x2C\x00\x00\x01\x90"
            .to_vec();
        push_record(&mut msg, name, 0x00_06, 1, 300, &soa_rec);
        // an.1: MX (pref, exchange)
        let mut mx = vec![0x00, 0x0A];
        mx.extend_from_slice(b"\x04mail\x07example\x03com\x00");
        push_record(&mut msg, name, 0x00_0F, 1, 300, &mx);
        // an.2: SRV (priority, weight, port, target)
        let mut srv = vec![0x00, 0x01, 0x00, 0x0A, 0x00, 0x50];
        srv.extend_from_slice(b"\x02ns\x07example\x03com\x00");
        push_record(&mut msg, name, 0x00_21, 1, 300, &srv);
        // an.3: TXT (two character-strings)
        push_record(
            &mut msg,
            name,
            0x00_10,
            1,
            300,
            &[0x04, b'h', b'e', b'l', b'l', 0x02, b'o', b'k'],
        );
        // an.4: CAA (flags, tag, value)
        push_record(
            &mut msg,
            name,
            0x01_01,
            1,
            300,
            &[0x80, 0x05, b'i', b's', b's', b'u', b'e', b'a', b'b'],
        );
        // an.5: DNAME (target)
        let mut dname = vec![0x05];
        dname.extend_from_slice(b"alias\x07example\x03com\x00");
        push_record(&mut msg, name, 0x00_27, 1, 300, &dname);
        // an.6: HINFO (cpu, os)
        push_record(
            &mut msg,
            name,
            0x00_0D,
            1,
            300,
            &[0x03, b'L', b'i', b'n', 0x03, b'x', b'6', b'4'],
        );
        // an.7: NAPTR (order, pref, flags, service, regexp, replacement)
        let mut naptr = vec![
            0x00, 0x64, 0x00, 0x64, 0x01, b'S', 0x06, b's', b'i', b'p', b'+', b'e', b'2', 0x00,
        ];
        naptr.extend_from_slice(b"\x07example\x03com\x00");
        push_record(&mut msg, name, 0x00_23, 1, 300, &naptr);
        // an.8: TLSA (usage, selector, matching, data)
        push_record(
            &mut msg,
            name,
            0x00_34,
            1,
            300,
            &[0x01, 0x01, 0x01, 0xab, 0xcd, 0xef],
        );
        // an.9: SSHFP (algorithm, fptype, fingerprint)
        push_record(&mut msg, name, 0x00_2C, 1, 300, &[0x02, 0x01, 0xab, 0xcd]);
        // ns.0: DS
        push_record(
            &mut msg,
            name,
            0x00_2B,
            1,
            300,
            &[0x12, 0x34, 0x08, 0x02, 0xab, 0xcd],
        );
        // ns.1: RRSIG (RFC 4034 §3.1: covered type, algorithm, labels,
        // orig ttl, expiration, inception, key tag, signer, sig).
        let mut rrsig = vec![
            0x00, 0x06, 0x08, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x00, 0x0E, 0x10, 0x00, 0x00,
            0x0E, 0x10, 0x12, 0x34,
        ];
        rrsig.extend_from_slice(b"\x07example\x03com\x00");
        rrsig.extend_from_slice(&[0xab, 0xcd]);
        push_record(&mut msg, name, 0x00_2E, 1, 300, &rrsig);
        // ns.2: NSEC (next name + type bitmap marking type 16).
        let mut nsec = vec![0x07];
        nsec.extend_from_slice(b"example\x03com\x00");
        nsec.extend_from_slice(&[0x00, 0x03, 0x00, 0x00, 0x80]);
        push_record(&mut msg, name, 0x00_2F, 1, 300, &nsec);
        // ns.3: DNSKEY (flags, protocol, algorithm, key)
        push_record(
            &mut msg,
            name,
            0x00_30,
            1,
            300,
            &[0x01, 0x00, 0x03, 0x08, 0xab, 0xcd],
        );
        // ar.0: HTTPS (priority 1, target root, alpn=h2 + port)
        let mut params = vec![0x00, 0x00, 0x00, 0x03, b'\x02', b'h', b'2']; // alpn
        params.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x00, 0x50]); // port 80
        let mut https = vec![0x00, 0x01, 0x00]; // priority 1, target root
        https.extend_from_slice(&params);
        push_record(&mut msg, name, 0x00_41, 1, 300, &https);

        let p = wrex_core::dissect::dissect(&registry(), &msg, "dns");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        let l = &p.layers[0];
        // SOA walk.
        assert_eq!(l.fields.get("an.0.type"), Some(&Value::Str("SOA".into())));
        assert_eq!(l.fields.get("an.0.soa.serial"), Some(&Value::Int(42)));
        assert_eq!(l.fields.get("an.0.soa.refresh"), Some(&Value::Int(100)));
        assert_eq!(l.fields.get("an.0.soa.retry"), Some(&Value::Int(200)));
        assert_eq!(l.fields.get("an.0.soa.expire"), Some(&Value::Int(300)));
        assert_eq!(l.fields.get("an.0.soa.minimum"), Some(&Value::Int(400)));
        assert_eq!(
            l.fields.get("an.0.soa.mname"),
            Some(&Value::Str("ns.example.com".into()))
        );
        // MX walk.
        assert_eq!(l.fields.get("an.1.mx.preference"), Some(&Value::Int(10)));
        assert_eq!(
            l.fields.get("an.1.mx.exchange"),
            Some(&Value::Str("mail.example.com".into()))
        );
        // SRV walk.
        assert_eq!(l.fields.get("an.2.srv.priority"), Some(&Value::Int(1)));
        assert_eq!(l.fields.get("an.2.srv.weight"), Some(&Value::Int(10)));
        assert_eq!(l.fields.get("an.2.srv.port"), Some(&Value::Int(80)));
        assert_eq!(
            l.fields.get("an.2.srv.target"),
            Some(&Value::Str("ns.example.com".into()))
        );
        // TXT walk (character-strings).
        assert!(matches!(
            l.fields.get("an.3.txt.strings"),
            Some(Value::List(items)) if items == &vec![
                Value::Str("hell".into()),
                Value::Str("ok".into()),
            ]
        ));
        // CAA walk.
        assert_eq!(l.fields.get("an.4.caa.flags"), Some(&Value::Int(0x80)));
        assert_eq!(
            l.fields.get("an.4.caa.tag"),
            Some(&Value::Str("issue".into()))
        );
        // DNAME walk.
        assert_eq!(
            l.fields.get("an.5.dname.target"),
            Some(&Value::Str("alias.example.com".into()))
        );
        // HINFO walk.
        assert_eq!(
            l.fields.get("an.6.hinfo.cpu"),
            Some(&Value::Str("Lin".into()))
        );
        assert_eq!(
            l.fields.get("an.6.hinfo.os"),
            Some(&Value::Str("x64".into()))
        );
        // NAPTR walk.
        assert_eq!(l.fields.get("an.7.naptr.order"), Some(&Value::Int(100)));
        assert_eq!(l.fields.get("an.7.naptr.pref"), Some(&Value::Int(100)));
        assert_eq!(
            l.fields.get("an.7.naptr.flags"),
            Some(&Value::Str("S".into()))
        );
        assert_eq!(
            l.fields.get("an.7.naptr.service"),
            Some(&Value::Str("sip+e2".into()))
        );
        assert_eq!(
            l.fields.get("an.7.naptr.regexp"),
            Some(&Value::Str("".into()))
        );
        assert_eq!(
            l.fields.get("an.7.naptr.replacement"),
            Some(&Value::Str("example.com".into()))
        );
        // TLSA walk.
        assert_eq!(l.fields.get("an.8.tlsa.usage"), Some(&Value::Int(1)));
        assert_eq!(l.fields.get("an.8.tlsa.selector"), Some(&Value::Int(1)));
        assert_eq!(l.fields.get("an.8.tlsa.matching"), Some(&Value::Int(1)));
        // SSHFP walk.
        assert_eq!(l.fields.get("an.9.sshfp.algorithm"), Some(&Value::Int(2)));
        assert_eq!(l.fields.get("an.9.sshfp.fptype"), Some(&Value::Int(1)));
        // DS walk (read-side DNSSEC).
        assert_eq!(l.fields.get("ns.0.type"), Some(&Value::Str("DS".into())));
        assert_eq!(l.fields.get("ns.0.ds.key_tag"), Some(&Value::Int(0x1234)));
        assert_eq!(l.fields.get("ns.0.ds.algorithm"), Some(&Value::Int(8)));
        assert_eq!(l.fields.get("ns.0.ds.digest_type"), Some(&Value::Int(2)));
        // RRSIG walk.
        assert_eq!(
            l.fields.get("ns.1.rrsig.covered"),
            Some(&Value::Str("SOA".into()))
        );
        assert_eq!(
            l.fields.get("ns.1.rrsig.key_tag"),
            Some(&Value::Int(0x1234))
        );
        assert_eq!(l.fields.get("ns.1.rrsig.labels"), Some(&Value::Int(1)));
        assert_eq!(l.fields.get("ns.1.rrsig.orig_ttl"), Some(&Value::Int(300)));
        assert_eq!(
            l.fields.get("ns.1.rrsig.signer"),
            Some(&Value::Str("example.com".into()))
        );
        // NSEC walk (type bitmap).
        assert_eq!(
            l.fields.get("ns.2.nsec.next"),
            Some(&Value::Str("example.com".into()))
        );
        assert!(matches!(
            l.fields.get("ns.2.nsec.types"),
            Some(Value::List(items)) if items == &vec![Value::Int(16)]
        ));
        // DNSKEY walk.
        assert_eq!(l.fields.get("ns.3.dnskey.flags"), Some(&Value::Int(0x0100)));
        assert_eq!(l.fields.get("ns.3.dnskey.protocol"), Some(&Value::Int(3)));
        // HTTPS walk: priority 1, root target, alpn + port params.
        assert_eq!(l.fields.get("ar.0.type"), Some(&Value::Str("HTTPS".into())));
        assert_eq!(l.fields.get("ar.0.svcb.priority"), Some(&Value::Int(1)));
        assert_eq!(l.fields.get("ar.0.svcb.0.key"), Some(&Value::Int(0)));
        assert!(matches!(
            l.fields.get("ar.0.svcb.0.alpn"),
            Some(Value::List(items)) if items == &vec![Value::Str("h2".into())]
        ));
        assert_eq!(l.fields.get("ar.0.svcb.1.key"), Some(&Value::Int(2)));
        assert_eq!(l.fields.get("ar.0.svcb.1.port"), Some(&Value::Int(80)));
    }

    /// 20a-2: malformed typed rdata degrades to a never-fatal anomaly
    /// (the typed_rdata rule) — never a panic, the raw bytes stay.
    #[test]
    fn malformed_typed_rdata_is_never_fatal() {
        // MX rdata of 1 byte (truncated).
        let mut msg = vec![
            0x00, 0x01, 0x81, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        msg.extend_from_slice(&[0x00, 0x00, 0x0F, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x01]);
        msg.push(0x42);
        let p = wrex_core::dissect::dissect(&registry(), &msg, "dns");
        assert!(
            p.anomalies.iter().any(|a| a.path == "dns.an.0.MX"),
            "{:?}",
            p.anomalies
        );
        assert!(matches!(
            p.layers[0].fields.get("an.0.rdata"),
            Some(Value::Bytes(_))
        ));
        // SVCB alias mode (priority 0) with params: pointed anomaly.
        let mut msg = vec![
            0x00, 0x01, 0x81, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let mut svcb = vec![0x00, 0x00, 0x00]; // priority 0, target root
        svcb.extend_from_slice(&[0x00, 0x02, 0x00, 0x02, 0x00, 0x50]); // params!
        msg.extend_from_slice(&[0x00, 0x00, 0x40, 0x00, 0x01, 0, 0, 0, 0]);
        msg.extend_from_slice(&(svcb.len() as u16).to_be_bytes());
        msg.extend_from_slice(&svcb);
        let p = wrex_core::dissect::dissect(&registry(), &msg, "dns");
        assert!(
            p.anomalies.iter().any(|a| a.path == "dns.ar.0.svcb"),
            "{:?}",
            p.anomalies
        );
    }
}
