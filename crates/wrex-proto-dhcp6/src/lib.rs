#![forbid(unsafe_code)]
//! wrex DHCPv6 codec (tranche 17c; RFC 8415): the 4-byte fixed header —
//! `msg_type` (1–13, named grammar `solicit|…|relay_reply` or raw) +
//! `trans_id` (3 bytes) — plus the options region (u16 code, u16 len
//! TLVs). udp dispatches 546/547 both sides into this codec (the
//! 67/68 pattern).
//!
//! The options region is craftable through the `options` list grammar
//! (`--dhcp6-options`, a `FieldKind::Str` field so the grammar is
//! CLI-reachable — see the `options` module): `client_id:HEX`,
//! `server_id:HEX` (DUIDs raw — structured typing deferred),
//! `ia_na:IAID[,t1,t2]` with `ia_addr:IP[,preferred,valid]`
//! continuations (IAADDR nests inside IA_NA, RFC 8415 §21.21 — the
//! record grammar's first nested use), `oro:N…`, `dns:IP…` (23),
//! `domain:NAME` (24, RFC 1035 label form), `elapsed:N`, `rapid` (14),
//! and the raw escape `hex:CODE:HEX`.
//!
//! Dissection renders every option as an indexed record of the
//! dissect-only `opt` section: `opt.N.code`, `opt.N.len`,
//! `opt.N.value` (raw hex, the wire truth) plus a typed subset per
//! code — `ip` (Ipv6: first dns server, IAADDR address),
//! `num` (Int: first oro code, elapsed time), `text` (Str: domain
//! list, names joined by `,`). IA_NA payloads nest ONE level of
//! sub-options as `opt.N.sub.M.*` records (`sub.M.code/len/value`
//! raw + `sub.M.ip` + `sub.M.preferred`/`sub.M.valid` for IAADDR);
//! deeper nesting flattens into `value`. Relay shapes (12/13)
//! dissect with the 34-byte extended fixed header — `hop_count`,
//! `link_addr`, `peer_addr` (dissect-only fields; crafting relay
//! messages is a recorded deferral, a pointed write-side rejection).

pub mod options;

use std::net::Ipv6Addr;
use std::sync::LazyLock;

use bytes::{BufMut, Bytes};
use wrex_core::dissect::{FieldSpan, LayerView};
use wrex_core::encode::EncodeCtx;
use wrex_core::error::DecodeError;
use wrex_core::schema::{FieldKind, FieldSchema, LayerSchema, Layout, RecordSchema};
use wrex_core::spec::LayerSpec;
use wrex_core::value::Value;
use wrex_core::{Anomaly, Codec, DecodeCtx, EncodeError, Next, ReadOutcome};

use crate::options::{
    OPT_DNS_SERVERS, OPT_DOMAIN_LIST, OPT_ELAPSED_TIME, OPT_IA_ADDR, OPT_IA_NA, OPT_ORO,
    decode_domain_names, parse_msg_type, parse_options, render_msg_type,
};

/// The kind string this codec implements (ADR 3).
pub const KIND: &str = "dhcp6";

/// The RFC 8415 §7.3 fixed header: msg-type(1) + transaction-id(3).
pub const HEADER_LEN: usize = 4;

/// The RFC 8415 §7.1 relay extended fixed header: msg-type(1) +
/// hop-count(1) + link-address(16) + peer-address(16).
pub const RELAY_HEADER_LEN: usize = 34;

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
            "msg_type",
            FieldKind::Str,
            "message type: solicit|advertise|request|confirm|renew|rebind|reply|release|decline|reconfigure|info_req|relay_forward|relay_reply or 1-13 (relay crafting deferred: 12/13 are pointed write errors)",
            Value::Str("solicit".into()),
        ),
        d(
            "trans_id",
            FieldKind::U32,
            "transaction id (3 bytes on the wire; over-wide values mask)",
            Value::Int(0),
        ),
        d(
            "options",
            FieldKind::Str,
            "options list grammar: client_id:HEX, server_id:HEX, ia_na:IAID[,t1,t2], ia_addr:IP[,preferred,valid], oro:N…, dns:IP…, domain:NAME, elapsed:N, rapid, hex:CODE:HEX",
            Value::Str(String::new()),
        ),
    ]
});

static OPT_FIELDS: LazyLock<Vec<FieldSchema>> = LazyLock::new(|| {
    vec![
        d(
            "code",
            FieldKind::U16,
            "option code (RFC 8415 §21; 3 = ia_na, 23 = dns servers)",
            Value::Int(0),
        ),
        d(
            "len",
            FieldKind::U16,
            "option data length in bytes",
            Value::Int(0),
        ),
        d(
            "value",
            FieldKind::Bytes,
            "raw option data hex (the wire truth)",
            Value::Bytes(Bytes::new()),
        ),
        d(
            "ip",
            FieldKind::Ipv6,
            "typed address: first dns server (23), IAADDR address (5)",
            Value::Ipv6(Ipv6Addr::UNSPECIFIED),
        ),
        d(
            "num",
            FieldKind::U32,
            "typed number: first oro code (6), elapsed time (8)",
            Value::Int(0),
        ),
        d(
            "text",
            FieldKind::Str,
            "typed string: domain search list (24, names joined by `,`)",
            Value::Str(String::new()),
        ),
    ]
});

static SUB_FIELDS: LazyLock<Vec<FieldSchema>> = LazyLock::new(|| {
    vec![
        d(
            "code",
            FieldKind::U16,
            "sub-option code (IA_NA payload; 5 = ia_addr)",
            Value::Int(0),
        ),
        d(
            "len",
            FieldKind::U16,
            "sub-option data length in bytes",
            Value::Int(0),
        ),
        d(
            "value",
            FieldKind::Bytes,
            "raw sub-option data hex (the wire truth)",
            Value::Bytes(Bytes::new()),
        ),
        d(
            "ip",
            FieldKind::Ipv6,
            "typed IAADDR address (sub-option 5)",
            Value::Ipv6(Ipv6Addr::UNSPECIFIED),
        ),
        d(
            "preferred",
            FieldKind::U32,
            "typed IAADDR preferred lifetime (sub-option 5)",
            Value::Int(0),
        ),
        d(
            "valid",
            FieldKind::U32,
            "typed IAADDR valid lifetime (sub-option 5)",
            Value::Int(0),
        ),
    ]
});

static RECORDS: LazyLock<Vec<RecordSchema>> = LazyLock::new(|| {
    vec![
        RecordSchema {
            name: "opt",
            fields: OPT_FIELDS.as_slice(),
            settable: false,
            max: None,
            doc: "DHCPv6 option TLVs after the 4-byte header (dissect-only; indexed paths opt.0.code, opt.0.value, …)",
        },
        RecordSchema {
            name: "sub",
            fields: SUB_FIELDS.as_slice(),
            settable: false,
            max: None,
            doc: "ONE level of nested sub-options inside an IA_NA record (dissect-only; indexed paths opt.0.sub.0.*, … — deeper nesting flattens into value)",
        },
    ]
});

pub static SCHEMA: LazyLock<LayerSchema> = LazyLock::new(|| LayerSchema {
    kind: KIND,
    rank: 40,
    parents: &[wrex_proto_udp::KIND],
    doc: "DHCPv6 (RFC 8415) over UDP 546/547: the 4-byte fixed header (msg_type 1-13 + the 3-byte trans_id) — everything else is options (u16 code, u16 len TLVs). Craft: --dhcp6-msg_type takes the named grammar (solicit|…|relay_reply or 1-13; relay 12/13 crafting is deferred — a pointed write error), --dhcp6-options takes the list grammar (client_id:HEX, server_id:HEX, ia_na:IAID[,t1,t2], ia_addr:IP[,preferred,valid] — IAADDR nests inside IA_NA, oro:N…, dns:IP…, domain:NAME, elapsed:N, rapid, hex:CODE:HEX). Dissect: every option lands in the dissect-only opt record section (opt.0.code/len/value raw + typed ip/num/text subset); IA_NA payloads render one level of sub-options as opt.N.sub.M.* records (deeper nesting flattens into value); relay shapes (12/13) dissect their 34-byte extended header (hop_count, link_addr, peer_addr — dissect-only). udp dispatches ports 546/547 into this codec. Deferrals: DHCPv6 auth (option 11), relay crafting, reconfigure/keyed surfaces, DUID structured typing, CLI-settable option records.",
    fields: FIELDS.as_slice(),
    records: RECORDS.as_slice(),
});

pub struct Dhcp6Codec;
pub static CODEC: Dhcp6Codec = Dhcp6Codec;

/// ADR 3 registration closure: self first, then the parent crate's.
pub fn register(r: &mut wrex_core::Registry) {
    if r.get(KIND).is_none() {
        r.register(&CODEC);
    }
    wrex_proto_udp::register(r);
}

/// Resolve the spec's `msg_type` (named grammar or raw Int) to its
/// wire byte. Relay (12/13) is a pointed write-side deferral error —
/// the relay extended header is dissect-only.
fn resolve_msg_type(spec: &LayerSpec, af: bool) -> Result<u8, EncodeError> {
    let bad = |detail: String| EncodeError::IncompatibleStack { detail };
    match spec.fields.get("msg_type") {
        Some(Value::Str(s)) if !s.is_empty() => {
            let n = parse_msg_type(s)
                .ok_or_else(|| bad(format!("dhcp6.msg_type: unknown message type `{s}`")))?;
            if n == 12 || n == 13 {
                return Err(bad(
                    "dhcp6.msg_type: crafting relay messages (12/13) is deferred — \
                     the 34-byte relay header is dissect-only"
                        .to_string(),
                ));
            }
            Ok(n)
        }
        Some(Value::Int(n)) => {
            let n = *n as u8;
            if n == 12 || n == 13 {
                return Err(bad(
                    "dhcp6.msg_type: crafting relay messages (12/13) is deferred — \
                     the 34-byte relay header is dissect-only"
                        .to_string(),
                ));
            }
            Ok(n)
        }
        _ => Ok(if af { 1 } else { 0 }), // solicit / unset
    }
}

/// Options region for a spec: the parsed list grammar (Str) or the
/// raw bytes (Bytes).
fn grammar_region(spec: &LayerSpec) -> Result<Vec<u8>, EncodeError> {
    match spec.fields.get("options") {
        Some(Value::Str(raw)) if !raw.is_empty() => parse_options(raw),
        Some(Value::Bytes(b)) => Ok(b.to_vec()),
        _ => Ok(Vec::new()),
    }
}

/// Typed sub-record emission inside one IA_NA option payload:
/// `opt.{i}.sub.{m}.*`. Returns the number of sub-records rendered.
fn read_ia_sub_records(
    data: &[u8],
    base: usize,
    at: usize,
    i: usize,
    fields: &mut std::collections::BTreeMap<String, Value>,
    spans: &mut std::collections::BTreeMap<String, FieldSpan>,
) {
    // RFC 8415 §21.21: the IA_NA fixed part is IAID + T1 + T2; the
    // sub-options follow. Shorter payloads carry no sub-records.
    if data.len() < 12 {
        return;
    }
    let mut cursor = 12usize;
    let mut m = 0usize;
    while cursor + 4 <= data.len() {
        let code = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
        let slen = u16::from_be_bytes([data[cursor + 2], data[cursor + 3]]) as usize;
        if cursor + 4 + slen > data.len() {
            break; // overrunning sub-option: never fatal, stop the walk
        }
        let sub = &data[cursor + 4..cursor + 4 + slen];
        let sdat = base + at + cursor + 4;
        let path = |f: &str| format!("opt.{i}.sub.{m}.{f}");
        spans.insert(
            path("code"),
            FieldSpan::Bytes(base + at + cursor..base + at + cursor + 2),
        );
        spans.insert(
            path("len"),
            FieldSpan::Bytes(base + at + cursor + 2..base + at + cursor + 4),
        );
        spans.insert(path("value"), FieldSpan::Bytes(sdat..sdat + slen));
        fields.insert(path("code"), Value::Int(code as u128));
        fields.insert(path("len"), Value::Int(slen as u128));
        fields.insert(path("value"), Value::Bytes(Bytes::copy_from_slice(sub)));
        // Typed subset: IAADDR (5) — address + lifetimes.
        if code == OPT_IA_ADDR && slen >= 24 {
            spans.insert(path("ip"), FieldSpan::Bytes(sdat..sdat + 16));
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&sub[..16]);
            fields.insert(path("ip"), Value::Ipv6(addr.into()));
            spans.insert(path("preferred"), FieldSpan::Bytes(sdat + 16..sdat + 20));
            fields.insert(
                path("preferred"),
                Value::Int(u32::from_be_bytes(sub[16..20].try_into().unwrap()) as u128),
            );
            spans.insert(path("valid"), FieldSpan::Bytes(sdat + 20..sdat + 24));
            fields.insert(
                path("valid"),
                Value::Int(u32::from_be_bytes(sub[20..24].try_into().unwrap()) as u128),
            );
        }
        m += 1;
        cursor += 4 + slen;
    }
}

impl Codec for Dhcp6Codec {
    fn schema(&self) -> &'static LayerSchema {
        &SCHEMA
    }

    fn header_len(&self, spec: &LayerSpec) -> Result<usize, EncodeError> {
        // Relay shapes never reach here (resolve_msg_type rejects them).
        Ok(HEADER_LEN + grammar_region(spec)?.len())
    }

    fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
        let af = ctx.autofill;
        let mt = resolve_msg_type(spec, af)?;
        ctx.buf.put_u8(mt);
        // trans_id: explicit wins; over-wide masks to the low 3 bytes.
        let tid = match spec.fields.get("trans_id") {
            Some(Value::Int(v)) => *v as u32,
            _ => 0,
        };
        ctx.buf
            .extend_from_slice(&(tid & 0xff_ffff).to_be_bytes()[1..4]);
        // The options region is the message tail (no end marker in v6).
        ctx.buf.extend_from_slice(&grammar_region(spec)?);
        Ok(())
    }

    fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
        if bytes.is_empty() {
            return ReadOutcome::Empty;
        }
        if bytes.len() < HEADER_LEN {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: KIND,
                    need: HEADER_LEN,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let base = ctx.offset;
        let mut fields: std::collections::BTreeMap<String, Value> =
            std::collections::BTreeMap::new();
        // Tranche 11b: parse-time spans for the dynamic options region
        // (the fixed header resolves through the static layouts table).
        let mut spans: std::collections::BTreeMap<String, FieldSpan> =
            std::collections::BTreeMap::new();
        let msg_type = bytes[0];
        fields.insert("msg_type".into(), Value::Str(render_msg_type(msg_type)));

        // Relay shapes (tranche 17c, RFC 8415 §7.1): msg-type 12/13
        // carry the 34-byte extended fixed header — hop-count,
        // link-address, peer-address (dissect-only fields; there is
        // no trans_id). A short (<34-byte) relay frame keeps the
        // plain 4-byte header (never fatal).
        let mut header = HEADER_LEN;
        let mut relay = false;
        if (msg_type == 12 || msg_type == 13) && bytes.len() >= RELAY_HEADER_LEN {
            relay = true;
            header = RELAY_HEADER_LEN;
            // hop-count sits at byte 1, not the trans_id slot.
            spans.insert("hop_count".into(), FieldSpan::Bytes(base + 1..base + 2));
            fields.insert("hop_count".into(), Value::Int(bytes[1] as u128));
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&bytes[2..18]);
            spans.insert("link_addr".into(), FieldSpan::Bytes(base + 2..base + 18));
            fields.insert("link_addr".into(), Value::Ipv6(addr.into()));
            addr.copy_from_slice(&bytes[18..34]);
            spans.insert("peer_addr".into(), FieldSpan::Bytes(base + 18..base + 34));
            fields.insert("peer_addr".into(), Value::Ipv6(addr.into()));
        } else {
            fields.insert(
                "trans_id".into(),
                Value::Int(u32::from_be_bytes([0, bytes[1], bytes[2], bytes[3]]) as u128),
            );
        }

        // Option TLVs (u16 code, u16 len): an option overrunning the
        // message stops with a never-fatal anomaly (the rest stays
        // payload); a dangling <4-byte tail stops silently (the dhcp
        // lenient-stop precedent).
        let mut consumed = header;
        let mut cursor = header;
        let mut i = 0usize;
        while cursor + 4 <= bytes.len() {
            let code = u16::from_be_bytes([bytes[cursor], bytes[cursor + 1]]);
            let olen = u16::from_be_bytes([bytes[cursor + 2], bytes[cursor + 3]]) as usize;
            if cursor + 4 + olen > bytes.len() {
                ctx.anomalies.push(Anomaly::new(
                    format!("dhcp6.opt.{i}"),
                    format!("option overruns the message (code {code}, need {olen} bytes)"),
                ));
                consumed = cursor;
                break;
            }
            let data = &bytes[cursor + 4..cursor + 4 + olen];
            let dat = base + cursor + 4;
            spans.insert(
                format!("opt.{i}.code"),
                FieldSpan::Bytes(base + cursor..base + cursor + 2),
            );
            spans.insert(
                format!("opt.{i}.len"),
                FieldSpan::Bytes(base + cursor + 2..base + cursor + 4),
            );
            spans.insert(format!("opt.{i}.value"), FieldSpan::Bytes(dat..dat + olen));
            fields.insert(format!("opt.{i}.code"), Value::Int(code as u128));
            fields.insert(format!("opt.{i}.len"), Value::Int(olen as u128));
            fields.insert(
                format!("opt.{i}.value"),
                Value::Bytes(Bytes::copy_from_slice(data)),
            );
            // Typed subset per code (never fatal on bad lengths).
            match code {
                OPT_ORO if olen >= 2 && olen.is_multiple_of(2) => {
                    spans.insert(format!("opt.{i}.num"), FieldSpan::Bytes(dat..dat + 2));
                    fields.insert(
                        format!("opt.{i}.num"),
                        Value::Int(u16::from_be_bytes([data[0], data[1]]) as u128),
                    );
                }
                OPT_ELAPSED_TIME if olen == 2 => {
                    spans.insert(format!("opt.{i}.num"), FieldSpan::Bytes(dat..dat + 2));
                    fields.insert(
                        format!("opt.{i}.num"),
                        Value::Int(u16::from_be_bytes([data[0], data[1]]) as u128),
                    );
                }
                OPT_DNS_SERVERS if olen >= 16 && olen.is_multiple_of(16) => {
                    // `ip` is the first address of the region.
                    spans.insert(format!("opt.{i}.ip"), FieldSpan::Bytes(dat..dat + 16));
                    let mut addr = [0u8; 16];
                    addr.copy_from_slice(&data[..16]);
                    fields.insert(format!("opt.{i}.ip"), Value::Ipv6(addr.into()));
                }
                OPT_DOMAIN_LIST => {
                    if let Some(names) = decode_domain_names(data) {
                        spans.insert(format!("opt.{i}.text"), FieldSpan::Bytes(dat..dat + olen));
                        fields.insert(format!("opt.{i}.text"), Value::Str(names));
                    }
                }
                OPT_IA_NA => {
                    // Nested sub-options, one level deep.
                    read_ia_sub_records(data, base, cursor + 4, i, &mut fields, &mut spans);
                }
                OPT_IA_ADDR if olen >= 16 => {
                    // A top-level IAADDR (rare): address typed.
                    spans.insert(format!("opt.{i}.ip"), FieldSpan::Bytes(dat..dat + 16));
                    let mut addr = [0u8; 16];
                    addr.copy_from_slice(&data[..16]);
                    fields.insert(format!("opt.{i}.ip"), Value::Ipv6(addr.into()));
                }
                _ => {}
            }
            i += 1;
            cursor += 4 + olen;
            consumed = cursor;
        }
        let _ = relay; // dissect-only; no further branching

        let view = LayerView {
            kind: KIND,
            span: ctx.offset..ctx.offset + consumed,
            field_spans: spans,
            fields,
        };
        // Terminal: post-option bytes stay payload.
        ReadOutcome::Layer(view, Some(Next::Payload))
    }

    /// Tranche 11b fixed layouts: the 4-byte RFC 8415 §7.3 header.
    /// The options region (`opt.N.*`, the nested `sub` records, and
    /// the relay fields) is codec-side (parse-time spans). `msg_type`
    /// is a Str-typed field over a raw span — the T14 rule: typed
    /// patches refuse pointedly, `wire:XX` speaks the byte.
    fn layouts(&self) -> &'static [(&'static str, Layout)] {
        &[
            ("msg_type", Layout::Bytes { at: 0, len: 1 }),
            ("trans_id", Layout::Bytes { at: 1, len: 3 }),
        ]
    }
}

#[cfg(feature = "test-util")]
pub mod strategy {
    //! proptest strategies for `LayerSpec` (behind `test-util`).
    use proptest::prelude::*;
    use wrex_core::spec::LayerSpec;
    use wrex_core::value::Value;

    use crate::options::MSG_TYPES;

    /// Valid dhcp6 specs: a message type from the canonical names
    /// (roundtrips exact — relay 12/13 excluded, crafting deferred),
    /// a random trans_id, and a small valid options-grammar pool.
    pub fn strategy() -> BoxedStrategy<LayerSpec> {
        let msg_type = proptest::sample::select(
            MSG_TYPES
                .iter()
                .filter(|(_, n)| *n != 12 && *n != 13)
                .map(|(n, _)| Value::Str(n.to_string()))
                .collect::<Vec<_>>(),
        );
        let opts = proptest::option::of(
            proptest::sample::select(vec![
                "client_id:hex:000102030405".to_string(),
                "server_id:hex:0001020304,elapsed:100".to_string(),
                "ia_na:7,300,600,ia_addr:2001:db8::10,3600,7200".to_string(),
                "ia_na:7,ia_addr:2001:db8::1,ia_addr:2001:db8::2,60,120".to_string(),
                "oro:23,24,39".to_string(),
                "dns:2001:db8::53,2001:db8::54".to_string(),
                "domain:wrex.example".to_string(),
                "elapsed:50,rapid".to_string(),
                "hex:40:0102".to_string(),
                "".to_string(),
            ])
            .prop_map(Value::Str),
        );
        // trans_id fits the 3-byte wire field (over-wide masks — the
        // in-crate unit covers that; the differential roundtrips the
        // typed value).
        (0u32..0x100_0000, msg_type, opts)
            .prop_map(|(tid, msg_type, opts)| {
                let mut fields = std::collections::BTreeMap::new();
                fields.insert("msg_type".to_string(), msg_type);
                fields.insert("trans_id".to_string(), Value::Int(tid as u128));
                if let Some(o) = opts {
                    if matches!(&o, Value::Str(s) if s.is_empty()) {
                        // the empty-grammar sample is the no-options case
                    } else {
                        fields.insert("options".to_string(), o);
                    }
                }
                LayerSpec::with_fields("dhcp6", fields)
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
        register(&mut r);
        r
    }

    fn af() -> EncodeOpts {
        EncodeOpts {
            autofill: true,
            ..Default::default()
        }
    }

    fn spec(fields: &[(&str, &str)]) -> LayerSpec {
        use wrex_core::value::parse_value;
        let mut map = std::collections::BTreeMap::new();
        for (k, v) in fields {
            let f = SCHEMA.field(k).expect("field in schema");
            map.insert(k.to_string(), parse_value(f, v).unwrap());
        }
        LayerSpec::with_fields(KIND, map)
    }

    /// ADR 3: udp is a real parent dep, so this registers the actual
    /// udp codec through the `register()` closure and dissects a
    /// crafted udp(546→547)→dhcp6 datagram end to end.
    #[test]
    fn udp_dispatches_into_dhcp6_with_real_codecs() {
        let mut r = Registry::empty();
        register(&mut r);
        let mut uf = std::collections::BTreeMap::new();
        uf.insert("sport".to_string(), Value::Int(546));
        uf.insert("dport".to_string(), Value::Int(547));
        let s = PacketSpec::new(
            vec![
                LayerSpec::with_fields(wrex_proto_udp::KIND, uf),
                spec(&[("msg_type", "solicit"), ("trans_id", "0x112233")]),
            ],
            None,
        );
        let enc = encode(&r, &s, &af()).unwrap();
        assert_eq!(
            &enc.bytes[8..],
            &[1, 0x11, 0x22, 0x33][..],
            "dhcp6 craft starts at the udp payload"
        );
        let p = wrex_core::dissect::dissect(&r, &enc.bytes, wrex_proto_udp::KIND);
        assert_eq!(
            p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
            vec![wrex_proto_udp::KIND, KIND],
            "udp ports 546/547 must chain into the real dhcp6 codec"
        );
    }

    #[test]
    fn msg_type_named_grammar() {
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec(&[("msg_type", "info_req")])], None),
            &af(),
        )
        .unwrap();
        assert_eq!(&enc.bytes[..], &[11, 0, 0, 0]);
        // raw numbers kept
        let enc = encode(
            &registry(),
            &PacketSpec::new(
                vec![LayerSpec::with_fields(
                    KIND,
                    [("msg_type".to_string(), Value::Int(7))]
                        .into_iter()
                        .collect(),
                )],
                None,
            ),
            &af(),
        )
        .unwrap();
        assert_eq!(&enc.bytes[..], &[7, 0, 0, 0]);
        // unknown name → pointed error
        assert!(
            encode(
                &registry(),
                &PacketSpec::new(vec![spec(&[("msg_type", "bogus")])], None),
                &af(),
            )
            .is_err()
        );
        // relay crafting is the pointed deferral
        for name in ["relay_forward", "relay_reply"] {
            assert!(
                encode(
                    &registry(),
                    &PacketSpec::new(vec![spec(&[("msg_type", name)])], None),
                    &af(),
                )
                .is_err(),
                "{name} must be a pointed write error"
            );
        }
    }

    #[test]
    fn trans_id_masks_and_roundtrips() {
        let enc = encode(
            &registry(),
            &PacketSpec::new(
                vec![LayerSpec::with_fields(
                    KIND,
                    [
                        ("msg_type".to_string(), Value::Str("solicit".into())),
                        ("trans_id".to_string(), Value::Int(0xaa_112233)),
                    ]
                    .into_iter()
                    .collect(),
                )],
                None,
            ),
            &Default::default(),
        )
        .unwrap();
        assert_eq!(&enc.bytes[..], &[1, 0x11, 0x22, 0x33]);
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, KIND);
        assert_eq!(
            p.layers[0].fields.get("trans_id"),
            Some(&Value::Int(0x112233))
        );
        assert_eq!(
            p.layers[0].fields.get("msg_type"),
            Some(&Value::Str("solicit".into()))
        );
    }

    #[test]
    fn options_grammar_records_and_nesting() {
        let s = spec(&[
            ("msg_type", "request"),
            (
                "options",
                "client_id:hex:000102030405,ia_na:7,300,600,ia_addr:2001:db8::10,3600,7200,oro:23,24,dns:2001:db8::53,domain:wrex.example",
            ),
        ]);
        let enc = encode(&registry(), &PacketSpec::new(vec![s], None), &af()).unwrap();
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, KIND);
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert!(p.payload.is_empty(), "the whole message is options");
        let fl = &p.layers[0].fields;
        assert_eq!(fl.get("opt.0.code"), Some(&Value::Int(1))); // client_id
        assert_eq!(fl.get("opt.1.code"), Some(&Value::Int(3))); // ia_na
        // nested IAADDR sub-record
        assert_eq!(
            fl.get("opt.1.sub.0.code"),
            Some(&Value::Int(OPT_IA_ADDR as u128))
        );
        assert_eq!(
            fl.get("opt.1.sub.0.ip"),
            Some(&Value::Ipv6("2001:db8::10".parse().unwrap()))
        );
        assert_eq!(fl.get("opt.1.sub.0.preferred"), Some(&Value::Int(3600)));
        assert_eq!(fl.get("opt.1.sub.0.valid"), Some(&Value::Int(7200)));
        assert_eq!(fl.get("opt.2.code"), Some(&Value::Int(6))); // oro
        assert_eq!(fl.get("opt.2.num"), Some(&Value::Int(23)));
        assert_eq!(fl.get("opt.3.code"), Some(&Value::Int(23))); // dns
        assert_eq!(
            fl.get("opt.3.ip"),
            Some(&Value::Ipv6("2001:db8::53".parse().unwrap()))
        );
        assert_eq!(fl.get("opt.4.code"), Some(&Value::Int(24))); // domain
        assert_eq!(
            fl.get("opt.4.text"),
            Some(&Value::Str("wrex.example".into()))
        );
        // raw value is always present
        assert!(matches!(fl.get("opt.4.value"), Some(Value::Bytes(_))));
        // no fifth option
        assert!(fl.get("opt.5.code").is_none());
    }

    #[test]
    fn relay_header_dissects() {
        let mut frame = vec![12u8, 0x0a];
        frame.extend_from_slice(&[0u8; 32]); // link + peer (::)
        frame.extend_from_slice(&[0x00, 0x01, 0x00, 0x02, 0xde, 0xad]); // a TLV tail
        let r = registry();
        let p = wrex_core::dissect::dissect(&r, &frame, KIND);
        assert_eq!(p.layers[0].kind, KIND);
        assert_eq!(p.layers[0].span, 0..40); // 34-byte header + one TLV
        assert_eq!(p.layers[0].fields.get("hop_count"), Some(&Value::Int(10)));
        assert!(
            !p.layers[0].fields.contains_key("trans_id"),
            "relay has no trans_id"
        );
        assert_eq!(
            p.layers[0].fields.get("msg_type"),
            Some(&Value::Str("relay_forward".into()))
        );
        // the TLV tail dissects as opt.0 (the options region starts
        // at 34 for relay shapes)
        assert_eq!(p.layers[0].fields.get("opt.0.code"), Some(&Value::Int(1)));
        assert_eq!(p.layers[0].fields.get("opt.0.len"), Some(&Value::Int(2)));
        assert!(p.payload.is_empty());
        // A SOLICIT-family type keeps the 4-byte header.
        let plain = [1u8, 0x11, 0x22, 0x33, 0xde];
        let p = wrex_core::dissect::dissect(&r, &plain, KIND);
        assert_eq!(p.layers[0].span, 0..4);
        assert_eq!(p.payload.len(), 1); // the dangling byte stays payload
    }

    #[test]
    fn truncated_and_overrun_inputs() {
        let r = registry();
        // 1-3 bytes: truncated → anomaly; partial data lands in the
        // synthetic `unknown` layer (never fatal).
        let p = wrex_core::dissect::dissect(&r, &[1, 0x11], KIND);
        assert_eq!(p.layers.len(), 1);
        assert_eq!(p.layers[0].kind, "unknown");
        assert_eq!(p.anomalies.len(), 1, "{:?}", p.anomalies);
        // empty: the Empty outcome
        let p = wrex_core::dissect::dissect(&r, &[], KIND);
        assert!(p.layers.is_empty() && p.anomalies.is_empty());
        // an option overrunning the message: never-fatal anomaly, the
        // rest stays payload
        let mut frame = vec![1u8, 1, 2, 3];
        frame.extend_from_slice(&[0, 23, 0, 40]); // dns declaring 40 bytes
        frame.push(0xff);
        let p = wrex_core::dissect::dissect(&r, &frame, KIND);
        assert!(
            p.anomalies.iter().any(|a| a.path == "dhcp6.opt.0"),
            "{:?}",
            p.anomalies
        );
        assert_eq!(p.layers[0].span.end, 4); // stops before the bad TLV
        assert_eq!(p.payload.len(), 5);
        // a dangling <4-byte tail: lenient silent stop
        let mut frame = vec![1u8, 1, 2, 3];
        frame.extend_from_slice(&[0, 8, 0]);
        let p = wrex_core::dissect::dissect(&r, &frame, KIND);
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.payload.len(), 3);
        // A relay type on a short (<34-byte) frame keeps the plain header.
        let p = wrex_core::dissect::dissect(&r, &[12, 1, 0, 0, 0, 0], KIND);
        assert_eq!(p.layers[0].span, 0..4);
        assert!(
            !p.layers[0].fields.contains_key("hop_count"),
            "short relay keeps the plain header"
        );
    }

    #[test]
    fn udp_dispatch_is_port_keyed() {
        let r = registry();
        let mut uf = std::collections::BTreeMap::new();
        uf.insert("sport".to_string(), Value::Int(546));
        uf.insert("dport".to_string(), Value::Int(9999)); // not 546/547
        let s = PacketSpec::new(vec![LayerSpec::with_fields(wrex_proto_udp::KIND, uf)], None);
        let enc = encode(&r, &s, &Default::default()).unwrap();
        let p = wrex_core::dissect::dissect(&r, &enc.bytes, wrex_proto_udp::KIND);
        assert_eq!(
            p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
            vec![wrex_proto_udp::KIND],
            "a non-546/547 port must not chain into dhcp6"
        );
    }
}
