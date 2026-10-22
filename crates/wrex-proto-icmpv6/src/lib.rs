#![forbid(unsafe_code)]
//! wrex ICMPv6 codec (RFC 4443 + NDP RFC 4861): type/code/checksum
//! with echo id/seq (types 128/129), full craft for NDP
//! RS(133)/RA(134)/NS(135)/NA(136), `rest` raw 4 bytes for other
//! types, and an dissect-only `opt` record section for NDP option
//! TLVs (SLLA/TLLA …). Rank 30, parent ipv6.
//!
//! The checksum covers the full message *and* the RFC 8200 §8.1 v6
//! pseudo-header (proto 58) — that is why this is its own codec, not
//! the tranche-1 icmp crate (whose `pseudo: None` cannot express it).

use std::net::Ipv6Addr;
use std::sync::LazyLock;

use bytes::{BufMut, Bytes};

use wrex_core::dissect::LayerView;
use wrex_core::encode::l4_pseudo;
use wrex_core::encode::{EncodeCtx, Patch, bytes_or_empty, flagset_or_default, int_or_default};
use wrex_core::error::DecodeError;
use wrex_core::schema::{
    ChecksumEnd, ChecksumStart, Derived, FieldKind, FieldSchema, LayerSchema, Layout, PseudoSource,
    RecordSchema,
};
use wrex_core::spec::LayerSpec;
use wrex_core::value::Value;

mod options;
use options::parse_ndp_options;
use wrex_core::{Anomaly, Codec, DecodeCtx, EncodeError, Next, ReadOutcome};

/// ICMPv6 message type numbers (RFC 4443 / RFC 4861).
pub const T_ECHO_REQ: u8 = 128;
pub const T_ECHO_REPLY: u8 = 129;
pub const T_RS: u8 = 133;
pub const T_RA: u8 = 134;
pub const T_NS: u8 = 135;
pub const T_NA: u8 = 136;

/// NDP option type numbers (RFC 4861 §4.6).
pub const OPT_SLLA: u8 = 1;
pub const OPT_TLLA: u8 = 2;
/// Prefix Information option (RFC 4861 §4.6.2) — tranche 17b.
pub const OPT_PI: u8 = 3;
/// MTU option (RFC 4861 §4.6.4) — tranche 17b.
pub const OPT_MTU: u8 = 5;

static FIELDS: LazyLock<Vec<FieldSchema>> = LazyLock::new(|| {
    let d = |name: &'static str, kind: FieldKind, doc: &'static str, default: Value| FieldSchema {
        name,
        kind,
        bit_names: &[],
        default,
        required: false,
        doc,
    };
    vec![
        d(
            "type",
            FieldKind::U8,
            "type (autofill: 128 echo request)",
            Value::Int(T_ECHO_REQ as u128),
        ),
        d("code", FieldKind::U8, "code (autofill: 0)", Value::Int(0)),
        d(
            "checksum",
            FieldKind::U16,
            "checksum over v6 pseudo-header+message (autofill: computed)",
            Value::Int(0),
        ),
        d(
            "echo.id",
            FieldKind::U16,
            "echo identifier (types 128/129)",
            Value::Int(0),
        ),
        d(
            "echo.seq",
            FieldKind::U16,
            "echo sequence (types 128/129)",
            Value::Int(0),
        ),
        FieldSchema {
            name: "rest",
            kind: FieldKind::Bytes,
            bit_names: &[],
            default: Value::Bytes(Bytes::new()),
            required: false,
            doc: "raw 4-byte rest of header (non-echo non-NDP types)",
        },
        d(
            "ndp.cur_hop_limit",
            FieldKind::U8,
            "router advertisement: current hop limit",
            Value::Int(64),
        ),
        FieldSchema {
            name: "ndp.ra_flags",
            kind: FieldKind::FlagSet,
            bit_names: &["m", "o"],
            default: Value::Int(0),
            required: false,
            doc: "router advertisement flags [m,o]; subpaths ndp.ra_flags.m / ndp.ra_flags.o",
        },
        d(
            "ndp.router_lifetime",
            FieldKind::U16,
            "router advertisement: router lifetime (seconds)",
            Value::Int(0),
        ),
        d(
            "ndp.reachable_time",
            FieldKind::U32,
            "router advertisement: reachable time (ms)",
            Value::Int(0),
        ),
        d(
            "ndp.retrans_timer",
            FieldKind::U32,
            "router advertisement: retransmit timer (ms)",
            Value::Int(0),
        ),
        FieldSchema {
            name: "ndp.na_flags",
            kind: FieldKind::FlagSet,
            bit_names: &["r", "s", "o"],
            default: Value::Int(0),
            required: false,
            doc: "neighbor advertisement flags [r,s,o]; subpaths ndp.na_flags.r / .s / .o",
        },
        d(
            "ndp.target",
            FieldKind::Ipv6,
            "neighbor solicitation/advertisement: target address",
            Value::Ipv6(Ipv6Addr::UNSPECIFIED),
        ),
    ]
});

static OPT_FIELDS: LazyLock<Vec<FieldSchema>> = LazyLock::new(|| {
    vec![
        FieldSchema {
            name: "type",
            kind: FieldKind::U8,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "option type (1 slla, 2 tlla)",
        },
        FieldSchema {
            name: "addr",
            kind: FieldKind::Mac,
            bit_names: &[],
            default: Value::Mac([0; 6]),
            required: false,
            doc: "link-layer address (slla/tlla options)",
        },
        FieldSchema {
            name: "data",
            kind: FieldKind::Bytes,
            bit_names: &[],
            default: Value::Bytes(Bytes::new()),
            required: false,
            doc: "raw option data (other options)",
        },
        // Tranche 17b: MLDv1 (RFC 2710) — the 16-byte multicast
        // address body of query/report/done (the v1 query's
        // max-response rides the `code` field, 1/10s units).
        FieldSchema {
            name: "mld.addr",
            kind: FieldKind::Ipv6,
            bit_names: &[],
            default: Value::Ipv6(std::net::Ipv6Addr::UNSPECIFIED),
            required: false,
            doc: "MLD multicast address (types 130/131/132; ff02::1 all-nodes, ff02::2 all-routers)",
        },
        // Tranche 17b: the NDP option list grammar, the write-side of
        // the dissect-only `opt` record section (the dhcp options
        // precedent — a Str field keeps it CLI-reachable).
        FieldSchema {
            name: "options",
            kind: FieldKind::Str,
            bit_names: &[],
            default: Value::Str(String::new()),
            required: false,
            doc: "NDP option TLV grammar, appended after the NDP body in order: slla:MAC, tlla:MAC, mtu:N, prefix:LEN,IP[,valid,preferred][,l][,a] (comma-continued), raw:TYPE:HEX",
        },
    ]
});

static RECORDS: LazyLock<Vec<RecordSchema>> = LazyLock::new(|| {
    vec![RecordSchema {
        name: "opt",
        fields: OPT_FIELDS.as_slice(),
        settable: false,
        max: None,
        doc: "NDP option TLVs after the NDP body (dissect-only; indexed paths opt.0.addr, …)",
    }]
});

/// The kind string this codec implements (ADR 3): the vocabulary is
/// compile-checked and symmetric across codecs.
pub const KIND: &str = "icmpv6";

pub static SCHEMA: LazyLock<LayerSchema> = LazyLock::new(|| LayerSchema {
    kind: KIND,
    rank: 30,
    parents: &[
        wrex_proto_ip6::KIND,
        // Tranche 17a: the stackable v6 ext headers (esp/nonext are
        // terminal — nothing stacks on them).
        wrex_proto_ip6ext::KIND_HOPOPTS,
        wrex_proto_ip6ext::KIND_ROUTING,
        wrex_proto_ip6ext::KIND_FRAG,
        wrex_proto_ip6ext::KIND_DSTOPTS,
        wrex_proto_ip6ext::KIND_AH,
    ],
    doc: "ICMPv6 (RFC 4443) + NDP (RFC 4861) over IPv6. type 128/129 (echo request/reply) expose echo.id and echo.seq. NDP craft: RS (133, header only), RA (134: ndp.cur_hop_limit, ndp.ra_flags [m,o], ndp.router_lifetime, ndp.reachable_time, ndp.retrans_timer), NS (135: ndp.target), NA (136: ndp.na_flags [r,s,o] + ndp.target). Other types render the 4-byte rest as icmpv6.rest raw bytes. checksum always covers the RFC 8200 §8.1 v6 pseudo-header (proto 58) plus the whole message. NDP options dissect into the opt record section (opt.0.addr, …) and CRAFT through the options list grammar (tranche 17b: slla:MAC, tlla:MAC, mtu:N, prefix:…, raw:TYPE:HEX). MLDv1 (tranche 17b): types 130/131/132 carry the mld.addr multicast body (the v1 query's max-response rides the code field). icmpv6 is terminal (the payload follows).",
    fields: FIELDS.as_slice(),
    records: RECORDS.as_slice(),
});

/// ICMPv6 codec unit. Register via [`register`] (the ADR-3 closure);
/// bespoke registries may use `&wrex_proto_icmpv6::CODEC` directly.
pub struct Icmp6Codec;

pub static CODEC: Icmp6Codec = Icmp6Codec;

/// ADR 3 registration closure: register self (dedup-guarded via
/// [`Registry::get`]), then the parent crates'. Self-first keeps
/// `standard()`'s fixed registration order byte-identical —
/// presence, not order, is the guarantee.
pub fn register(r: &mut wrex_core::Registry) {
    if r.get(KIND).is_none() {
        r.register(&CODEC);
    }
    wrex_proto_ip6::register(r);
    // Tranche 17a: the ext family is a parent now (icmpv6 stacks on
    // the five non-terminal kinds — ADR 3: parents are deps).
    wrex_proto_ip6ext::register(r);
}

/// MLDv1 message types (RFC 2710; tranche 17b): query 130 (the
/// max-response rides the CODE field, 1/10s units), report 131,
/// done 132 — a 16-byte multicast-address body each.
pub const T_MLD_QUERY: u8 = 130;
pub const T_MLD_REPORT: u8 = 131;
pub const T_MLD_DONE: u8 = 132;

fn is_mld(t: u8) -> bool {
    matches!(t, T_MLD_QUERY | T_MLD_REPORT | T_MLD_DONE)
}

fn is_echo(t: u8) -> bool {
    t == T_ECHO_REQ || t == T_ECHO_REPLY
}

fn is_ndp(t: u8) -> bool {
    (T_RS..=T_NA).contains(&t)
}

/// NDP body length after the 8-byte icmpv6 header: RA +8, NS/NA +16.
fn ndp_body_len(t: u8) -> usize {
    match t {
        T_RS => 0,
        T_RA => 8,
        T_NS | T_NA => 16,
        T_MLD_QUERY | T_MLD_REPORT | T_MLD_DONE => 16,
        _ => 0,
    }
}

impl Codec for Icmp6Codec {
    fn schema(&self) -> &'static LayerSchema {
        &SCHEMA
    }

    fn header_len(&self, spec: &LayerSpec) -> Result<usize, EncodeError> {
        let af = true; // header_len only sizes the buffer; type is explicit
        let t = int_or_default(spec, &FIELDS[0], af) as u8;
        let mut len = 8 + ndp_body_len(t);
        // Tranche 17b: the NDP option list grammar appends after the
        // body (only NDP types carry options per RFC 4861).
        if is_ndp(t)
            && let Some(Value::Str(raw)) = spec.fields.get("options")
        {
            len += parse_ndp_options(raw)?.len();
        }
        Ok(len)
    }

    fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
        let af = ctx.autofill;
        let start = ctx.buf.len();
        let t = int_or_default(spec, &FIELDS[0], af) as u8;
        ctx.buf.put_u8(t);
        ctx.buf.put_u8(int_or_default(spec, &FIELDS[1], af) as u8);
        let at_ck = ctx.buf.len();
        let ck_explicit = spec.fields.contains_key("checksum");
        if let Some(Value::Int(v)) = spec.fields.get("checksum") {
            ctx.buf.put_u16(*v as u16);
        } else {
            ctx.buf.put_u16(0); // checksum placeholder
        }
        // Rest of header + NDP body.
        if is_echo(t) {
            ctx.buf.put_u16(int_or_default(spec, &FIELDS[3], af) as u16); // echo.id
            ctx.buf.put_u16(int_or_default(spec, &FIELDS[4], af) as u16); // echo.seq
        } else {
            match t {
                T_RS => {
                    ctx.buf.put_u32(0); // reserved
                }
                T_RA => {
                    ctx.buf.put_u8(int_or_default(spec, &FIELDS[6], af) as u8); // cur_hop_limit
                    // [m,o] is a 2-bit aggregate (m=bit1, o=bit0): place at
                    // the top of the flags byte (M 0x80 | O 0x40).
                    ctx.buf
                        .put_u8(((flagset_or_default(spec, &FIELDS[7], af) as u8) & 0b11) << 6);
                    ctx.buf.put_u16(int_or_default(spec, &FIELDS[8], af) as u16); // router_lifetime
                    ctx.buf.put_u32(int_or_default(spec, &FIELDS[9], af) as u32); // reachable_time
                    ctx.buf
                        .put_u32(int_or_default(spec, &FIELDS[10], af) as u32); // retrans_timer
                }
                T_NS | T_NA => {
                    if t == T_NA {
                        // [r,s,o] is a 3-bit aggregate (r=bit2, s=bit1,
                        // o=bit0): place at the top of the flags byte
                        // (R 0x80 | S 0x40 | O 0x20).
                        ctx.buf.put_u8(
                            ((flagset_or_default(spec, &FIELDS[11], af) as u8) & 0b111) << 5,
                        );
                    } else {
                        ctx.buf.put_u8(0); // reserved
                    }
                    ctx.buf.put_u8(0);
                    ctx.buf.put_u8(0);
                    ctx.buf.put_u8(0);
                    ctx.buf
                        .extend_from_slice(&ipv6_field(spec, "ndp.target", af).octets());
                }
                _ => {
                    let mut rest = [0u8; 4];
                    let bytes = bytes_or_empty(spec, "rest");
                    for (i, b) in bytes.iter().take(4).enumerate() {
                        rest[i] = *b;
                    }
                    ctx.buf.extend_from_slice(&rest);
                }
            }
        }
        // MLDv1 bodies (tranche 17b): the 16-byte multicast address.
        if is_mld(t) {
            let addr = match spec.fields.get("mld.addr") {
                Some(Value::Ipv6(a)) => *a,
                _ if af => "ff02::1".parse().unwrap(), // all-nodes default
                _ => std::net::Ipv6Addr::UNSPECIFIED,
            };
            ctx.buf.extend_from_slice(&addr.octets());
        }
        // Checksum over the whole message (header + body + payload) with
        // the v6 pseudo-header (proto 58) — facts were recorded by ipv6.
        let pseudo = ctx.facts.net.map(|n| l4_pseudo(n, 58));
        // Tranche 17b: the NDP option list grammar (the dhcp
        // options-grammar architecture) appends after the NDP body,
        // order preserved. Options on non-NDP types are a pointed
        // error (echo payloads stay payloads, RFC 4861 §4.6).
        if let Some(Value::Str(raw)) = spec.fields.get("options") {
            if !is_ndp(t) {
                return Err(EncodeError::IncompatibleStack {
                    detail: "icmpv6.options: NDP options only follow NDP bodies".into(),
                });
            }
            ctx.buf.extend_from_slice(&parse_ndp_options(raw)?);
        }
        // Tranche 17a: the checksum covers the upper-layer packet —
        // with a v6 ext chain that includes the ext headers (RFC 8200
        // §8.1); equals this layer's own start on ext-free stacks.
        let ck_start = ctx.facts.upper_start.unwrap_or(start);
        ctx.defer(Patch::Checksum {
            at: at_ck,
            start: ck_start,
            end: None, // header + NDP body + payload
            pseudo,
            explicit: ck_explicit,
            path: "icmpv6.checksum",
        });
        Ok(())
    }

    fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
        if bytes.is_empty() {
            return ReadOutcome::Empty;
        }
        if bytes.len() < 8 {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: "icmpv6",
                    need: 8,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let t = bytes[0];
        let code = bytes[1];
        let found_ck = u16::from_be_bytes([bytes[2], bytes[3]]);
        let need = 8 + ndp_body_len(t);
        if bytes.len() < need {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: "icmpv6",
                    need,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }

        let mut fields = std::collections::BTreeMap::new();
        fields.insert("type".into(), Value::Int(t as u128));
        fields.insert("code".into(), Value::Int(code as u128));
        fields.insert("checksum".into(), Value::Int(found_ck as u128));

        // NDP options: TLVs after the NDP body (only NDP types carry
        // them per RFC 4861; echo payloads stay payloads).
        let body_end = need;
        let mut opt_end = body_end;
        if is_ndp(t) {
            let mut cursor = body_end;
            let mut i = 0usize;
            while bytes.len() >= cursor + 2 {
                let otype = bytes[cursor];
                let olen = bytes[cursor + 1] as usize; // units of 8 bytes
                if olen == 0 {
                    break; // invalid: stop consuming
                }
                let ototal = olen * 8;
                if cursor + ototal > bytes.len() {
                    // An option that overruns the message stops the parse
                    // (lenient: the rest stays payload — the engine is
                    // never fatal, and random payloads behind NDP bodies
                    // are common). No anomaly: nothing distinguishes a
                    // truncated capture from trailing garbage here.
                    break;
                }
                fields.insert(format!("opt.{i}.type"), Value::Int(otype as u128));
                let data = &bytes[cursor + 2..cursor + ototal];
                match otype {
                    OPT_SLLA | OPT_TLLA => {
                        let mut mac = [0u8; 6];
                        for (j, b) in data.iter().take(6).enumerate() {
                            mac[j] = *b;
                        }
                        fields.insert(format!("opt.{i}.addr"), Value::Mac(mac));
                    }
                    // Tranche 17b: the typed grammar surface — MTU and
                    // the plastered PI option (RFC 4861 §4.6.2/§4.6.4).
                    OPT_MTU if data.len() >= 6 => {
                        // Wire: type, len, reserved(2), mtu(4) — the
                        // value starts 2 bytes into the region.
                        fields.insert(
                            format!("opt.{i}.mtu"),
                            Value::Int(
                                u32::from_be_bytes([data[2], data[3], data[4], data[5]]) as u128
                            ),
                        );
                    }
                    OPT_PI if data.len() >= 30 => {
                        fields.insert(
                            format!("opt.{i}.prefix_len"),
                            Value::Int(bytes[cursor + 2] as u128),
                        );
                        let fl = bytes[cursor + 3];
                        let mut names = Vec::new();
                        if fl & 0x80 != 0 {
                            names.push(Value::Str("l".into()));
                        }
                        if fl & 0x40 != 0 {
                            names.push(Value::Str("a".into()));
                        }
                        fields.insert(format!("opt.{i}.flags"), Value::List(names));
                        // Wire after the TLV prefix: plen, flags,
                        // reserved(4), prefix(16), valid(4),
                        // preferred(4) — 30 bytes.
                        fields.insert(
                            format!("opt.{i}.prefix"),
                            Value::Ipv6(std::net::Ipv6Addr::from([
                                data[6], data[7], data[8], data[9], data[10], data[11], data[12],
                                data[13], data[14], data[15], data[16], data[17], data[18],
                                data[19], data[20], data[21],
                            ])),
                        );
                        fields.insert(
                            format!("opt.{i}.valid"),
                            Value::Int(
                                u32::from_be_bytes([data[22], data[23], data[24], data[25]])
                                    as u128,
                            ),
                        );
                        fields.insert(
                            format!("opt.{i}.preferred"),
                            Value::Int(
                                u32::from_be_bytes([data[26], data[27], data[28], data[29]])
                                    as u128,
                            ),
                        );
                    }
                    _ => {
                        fields.insert(
                            format!("opt.{i}.data"),
                            Value::Bytes(Bytes::copy_from_slice(data)),
                        );
                    }
                }
                i += 1;
                cursor += ototal;
                opt_end = cursor;
            }
        }

        // MLDv1 bodies (tranche 17b): the 16-byte multicast address
        // (the option pass is NDP-only, so MLD bytes were skipped).
        if is_mld(t) && bytes.len() >= need {
            fields.insert(
                "mld.addr".into(),
                Value::Ipv6(std::net::Ipv6Addr::from([
                    bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                    bytes[15], bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21],
                    bytes[22], bytes[23],
                ])),
            );
        }
        // Body fields per type (after the option pass so echo payloads
        // never masquerade as NDP data).
        if is_echo(t) {
            fields.insert(
                "echo.id".into(),
                Value::Int(u16::from_be_bytes([bytes[4], bytes[5]]) as u128),
            );
            fields.insert(
                "echo.seq".into(),
                Value::Int(u16::from_be_bytes([bytes[6], bytes[7]]) as u128),
            );
        } else {
            match t {
                T_RA => {
                    fields.insert("ndp.cur_hop_limit".into(), Value::Int(bytes[4] as u128));
                    let agg = bytes[5] & 0xc0;
                    let mut names: Vec<Value> = Vec::new();
                    if agg & 0b1000_0000 != 0 {
                        names.push(Value::Str("m".into()));
                    }
                    if agg & 0b0100_0000 != 0 {
                        names.push(Value::Str("o".into()));
                    }
                    fields.insert("ndp.ra_flags".into(), Value::List(names));
                    fields.insert(
                        "ndp.router_lifetime".into(),
                        Value::Int(u16::from_be_bytes([bytes[6], bytes[7]]) as u128),
                    );
                    fields.insert(
                        "ndp.reachable_time".into(),
                        Value::Int(
                            u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]) as u128,
                        ),
                    );
                    fields.insert(
                        "ndp.retrans_timer".into(),
                        Value::Int(
                            u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]])
                                as u128,
                        ),
                    );
                }
                T_NS | T_NA => {
                    if t == T_NA {
                        let agg = bytes[4] & 0xe0;
                        let mut names: Vec<Value> = Vec::new();
                        if agg & 0b1000_0000 != 0 {
                            names.push(Value::Str("r".into()));
                        }
                        if agg & 0b0100_0000 != 0 {
                            names.push(Value::Str("s".into()));
                        }
                        if agg & 0b0010_0000 != 0 {
                            names.push(Value::Str("o".into()));
                        }
                        fields.insert("ndp.na_flags".into(), Value::List(names));
                    }
                    let target = Ipv6Addr::from([
                        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                        bytes[15], bytes[16], bytes[17], bytes[18], bytes[19], bytes[20],
                        bytes[21], bytes[22], bytes[23],
                    ]);
                    fields.insert("ndp.target".into(), Value::Ipv6(target));
                }
                _ => {
                    fields.insert(
                        "rest".into(),
                        Value::Bytes(Bytes::copy_from_slice(&bytes[4..8])),
                    );
                }
            }
        }

        // Checksum verify (non-fatal) when the v6 parent recorded facts:
        // pseudo-header (proto 58) + the upper-layer packet (tranche 17a:
        // v6 ext headers included, RFC 8200 §8.1), ck field zeroed.
        // With the engine's frame lookback + a recorded upper_start the
        // range starts at the first ext header; the legacy `bytes`
        // slice otherwise (identical on ext-free stacks).
        if let Some(net) = ctx.facts.net {
            let mut acc = wrex_core::ChecksumAccumulator::new();
            let upper = ctx
                .facts
                .upper_start
                .filter(|&u| u <= ctx.offset && u < ctx.frame.len());
            if let (Some(upper), true) = (upper, !ctx.frame.is_empty()) {
                let upper_len = ctx.frame.len() - upper;
                l4_pseudo(net, 58).accumulate_into(&mut acc, upper_len);
                acc.add_bytes(&ctx.frame[upper..ctx.offset + 2]);
                acc.add_u16(0);
                acc.add_bytes(&ctx.frame[ctx.offset + 4..]);
            } else {
                l4_pseudo(net, 58).accumulate_into(&mut acc, bytes.len());
                acc.add_bytes(&bytes[..2]);
                acc.add_u16(0);
                acc.add_bytes(&bytes[4..]);
            }
            let computed = acc.value();
            if found_ck != computed {
                ctx.anomalies.push(Anomaly::new(
                    "icmpv6.checksum",
                    format!("mismatch (computed 0x{computed:04x}, found 0x{found_ck:04x})"),
                ));
            }
        }

        let view = LayerView {
            kind: "icmpv6",
            span: ctx.offset..ctx.offset + opt_end,
            field_spans: Default::default(),
            fields,
        };
        // Terminal: the remaining bytes (after NDP options) are payload.
        ReadOutcome::Layer(view, Some(Next::Payload))
    }

    /// Tranche 11b fixed layouts (type-dependent 4..24 tail; NDP flags
    /// are bit windows; `opt` record sections stay None until their
    /// tranche-11b slice).
    fn layouts(&self) -> &'static [(&'static str, Layout)] {
        &[
            ("type", Layout::Bytes { at: 0, len: 1 }),
            ("code", Layout::Bytes { at: 1, len: 1 }),
            ("checksum", Layout::Bytes { at: 2, len: 2 }),
            ("echo.id", Layout::Bytes { at: 4, len: 2 }),
            ("echo.seq", Layout::Bytes { at: 6, len: 2 }),
            ("rest", Layout::Bytes { at: 4, len: 4 }),
            ("ndp.cur_hop_limit", Layout::Bytes { at: 4, len: 1 }),
            (
                "ndp.ra_flags",
                Layout::Bits {
                    at: 5,
                    shift: 0,
                    width: 2,
                },
            ),
            ("ndp.router_lifetime", Layout::Bytes { at: 6, len: 2 }),
            ("ndp.reachable_time", Layout::Bytes { at: 8, len: 4 }),
            ("ndp.retrans_timer", Layout::Bytes { at: 12, len: 4 }),
            (
                "ndp.na_flags",
                Layout::Bits {
                    at: 4,
                    shift: 0,
                    width: 3,
                },
            ),
            ("ndp.target", Layout::Bytes { at: 8, len: 16 }),
        ]
    }

    /// `checksum` covers the message to the frame end over the v6
    /// pseudo-header (proto 58, RFC 8200 §8.1 — always FromFacts since
    /// the parent is ipv6).
    fn derived(&self) -> &'static [Derived] {
        &[Derived::Checksum {
            field: "checksum",
            at: 2,
            start: ChecksumStart::UpperPacket,
            end: ChecksumEnd::Frame,
            pseudo: PseudoSource::FromFacts,
        }]
    }
}

/// IPv6 field accessor (explicit or default when autofilling).
fn ipv6_field(spec: &LayerSpec, name: &str, autofill: bool) -> Ipv6Addr {
    match SCHEMA.field(name) {
        Some(f) => wrex_core::encode::ipv6_or_default(spec, f, autofill),
        None => Ipv6Addr::UNSPECIFIED,
    }
}

#[cfg(feature = "test-util")]
pub mod strategy {
    //! proptest strategies for `LayerSpec` (behind `test-util`).
    use proptest::prelude::*;
    use wrex_core::spec::LayerSpec;
    use wrex_core::value::Value;

    use crate::{T_ECHO_REPLY, T_ECHO_REQ, T_NA, T_NS, T_RA, T_RS};

    /// Valid icmpv6 specs: echo types (id/seq) or NDP types with
    /// type-consistent bodies, or another type with a 4-byte rest.
    pub fn strategy() -> BoxedStrategy<LayerSpec> {
        (
            proptest::sample::select(vec![
                T_ECHO_REQ,
                T_ECHO_REPLY,
                T_RS,
                T_RA,
                T_NS,
                T_NA,
                1, // generic type (rest)
            ]),
            any::<u16>(),
            any::<u16>(),
            any::<u8>(),
            (0u32..0x10_0000),
            proptest::array::uniform16(any::<u8>()),
        )
            .prop_map(|(t, id, seq, hop, lifetime, target)| {
                let mut fields = std::collections::BTreeMap::new();
                fields.insert("type".to_string(), Value::Int(t as u128));
                match t {
                    T_ECHO_REQ | T_ECHO_REPLY => {
                        fields.insert("echo.id".to_string(), Value::Int(id as u128));
                        fields.insert("echo.seq".to_string(), Value::Int(seq as u128));
                    }
                    T_RA => {
                        fields.insert("ndp.cur_hop_limit".to_string(), Value::Int(hop as u128));
                        fields.insert(
                            "ndp.router_lifetime".to_string(),
                            Value::Int(lifetime as u128),
                        );
                    }
                    T_NS | T_NA => {
                        fields.insert(
                            "ndp.target".to_string(),
                            Value::Ipv6(std::net::Ipv6Addr::from(target)),
                        );
                    }
                    // RS: header only; the generic types carry a 4-byte rest.
                    T_RS => {}
                    _ => {
                        fields.insert(
                            "rest".to_string(),
                            Value::Bytes(bytes::Bytes::from(vec![1, 2, 3, 4])),
                        );
                    }
                }
                LayerSpec::with_fields("icmpv6", fields)
            })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use wrex_core::Registry;
    use wrex_core::dissect::Facts;
    use wrex_core::encode::{EncodeOpts, encode};
    use wrex_core::spec::PacketSpec;
    use wrex_core::value::parse_value;

    fn f(name: &str) -> &'static FieldSchema {
        SCHEMA.field(name).unwrap()
    }

    fn icmp6_spec(fields: &[(&str, &str)]) -> LayerSpec {
        let mut map = BTreeMap::new();
        for (k, v) in fields {
            if *k == "rest" {
                map.insert(
                    k.to_string(),
                    Value::Bytes(Bytes::from(
                        wrex_core::value::parse_hex_bytes(v.trim_start_matches("hex:")).unwrap(),
                    )),
                );
                continue;
            }
            map.insert(k.to_string(), parse_value(f(k), v).unwrap());
        }
        LayerSpec::with_fields("icmpv6", map)
    }

    fn registry() -> Registry {
        let mut r = Registry::empty();
        r.register(&CODEC);
        r
    }

    fn lo6_opts() -> EncodeOpts {
        EncodeOpts {
            autofill: true,
            strict: false,
            facts: Facts {
                net: Some(wrex_core::dissect::NetFacts::V6 {
                    src: "::1".parse().unwrap(),
                    dst: "::1".parse().unwrap(),
                    next_header: 58,
                }),
                ..Default::default()
            },
        }
    }

    /// RFC 4443-style independent verification helper: checksum over the
    /// v6 pseudo-header (src ::1, dst ::1 — the lo6_opts facts) + message.
    fn checksum_over(msg: &[u8]) -> u16 {
        let ones = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut acc = wrex_core::ChecksumAccumulator::new();
        acc.add_bytes(&ones); // src ::1
        acc.add_bytes(&ones); // dst ::1
        acc.add_bytes(&(msg.len() as u32).to_be_bytes());
        acc.add_bytes(&[0, 58]);
        acc.add_bytes(msg);
        acc.value()
    }

    /// ADR 3: ipv6 is a real parent dep, so this registers the actual
    /// ipv6 codec through the `register()` closure and dissects a
    /// crafted ipv6→icmpv6 packet end to end — the string dispatch
    /// table can no longer drift from the kinds it names (no stand-in).
    #[test]
    fn ipv6_dispatches_into_icmpv6_with_real_codecs() {
        let mut r = wrex_core::Registry::empty();
        register(&mut r);
        let spec = wrex_core::spec::PacketSpec::new(
            vec![
                wrex_core::spec::LayerSpec::new(wrex_proto_ip6::KIND),
                icmp6_spec(&[]),
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
        let p = wrex_core::dissect::dissect(&r, &enc.bytes, wrex_proto_ip6::KIND);
        assert_eq!(
            p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
            vec![wrex_proto_ip6::KIND, KIND],
            "ipv6.next_header 58 must chain into the real icmpv6 codec"
        );
    }

    /// Tranche 17a: icmpv6 under a v6 extension chain — [ipv6,
    /// hopopts, icmpv6] crafts with the ext bytes counted into the
    /// checksum (RFC 8200 §8.1) and dissects anomaly-free through the
    /// real codecs.
    #[test]
    fn ext_chain_checksum_covers_hopopts() {
        let mut r = wrex_core::Registry::empty();
        register(&mut r);
        let mut hf = std::collections::BTreeMap::new();
        hf.insert(
            "options".to_string(),
            wrex_core::Value::Bytes(bytes::Bytes::from_static(&[
                0x01, 0x04, 0x00, 0x00, 0x00, 0x00,
            ])),
        );
        let spec = wrex_core::spec::PacketSpec::new(
            vec![
                wrex_core::spec::LayerSpec::new(wrex_proto_ip6::KIND),
                wrex_core::spec::LayerSpec::with_fields(wrex_proto_ip6ext::KIND_HOPOPTS, hf),
                icmp6_spec(&[]),
            ],
            None,
        );
        let enc = encode(
            &r,
            &spec,
            &wrex_core::encode::EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        let p = wrex_core::dissect::dissect(&r, &enc.bytes, wrex_proto_ip6::KIND);
        assert_eq!(
            p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
            vec![
                wrex_proto_ip6::KIND,
                wrex_proto_ip6ext::KIND_HOPOPTS,
                "icmpv6"
            ]
        );
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
    }

    /// Tranche 17b: the NDP option list grammar round-trips through
    /// the real codecs — slla/tlla/mtu/prefix (with lifetimes + l/a
    /// flags) and the raw escape, order preserved; the PI option
    /// dissects into its typed subpaths; options on echo types are
    /// the pointed error.
    /// Tranche 17b: the MLDv1 triad (RFC 2710) — query 130 (max_resp
    /// rides the code field, 1/10s units), report 131, done 132, each
    /// carrying the 16-byte multicast address body.
    #[test]
    fn mldv1_triad_roundtrip() {
        let mut r = wrex_core::Registry::empty();
        register(&mut r);
        for (t, code) in [(130u8, 10u8), (131, 0), (132, 0)] {
            let mut f = std::collections::BTreeMap::new();
            f.insert("type".to_string(), Value::Int(t as u128));
            f.insert("code".to_string(), Value::Int(code as u128));
            f.insert(
                "mld.addr".to_string(),
                Value::Ipv6("ff02::1".parse().unwrap()),
            );
            let spec = wrex_core::spec::PacketSpec::new(
                vec![
                    wrex_core::spec::LayerSpec::new(wrex_proto_ip6::KIND),
                    wrex_core::spec::LayerSpec::with_fields(KIND, f),
                ],
                None,
            );
            let enc = encode(
                &r,
                &spec,
                &wrex_core::encode::EncodeOpts {
                    autofill: true,
                    ..Default::default()
                },
            )
            .unwrap();
            let p = wrex_core::dissect::dissect(&r, &enc.bytes, wrex_proto_ip6::KIND);
            assert!(p.anomalies.is_empty(), "type {t}: {:?}", p.anomalies);
            let l = &p.layers[1];
            assert_eq!(l.fields.get("type"), Some(&Value::Int(t as u128)));
            assert_eq!(l.fields.get("code"), Some(&Value::Int(code as u128)));
            assert_eq!(
                l.fields.get("mld.addr"),
                Some(&Value::Ipv6("ff02::1".parse().unwrap())),
                "type {t}: the multicast body must round-trip"
            );
        }
    }

    /// Tranche 17b: the NS-SLLA byte-identity cross-check — the codec's
    /// craft vs the `wrex-io::ndp` driver hand-roll (two in-tree
    /// lineages of the same wire bytes, the internal inversion-rule
    /// cross-check; the driver is the RFC-verified one from T10b).
    #[test]
    fn ns_slla_matches_driver_handroll() {
        let iface_mac = [0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55];
        let src: std::net::Ipv6Addr = "fe80::1234".parse().unwrap();
        let target: std::net::Ipv6Addr = "fe80::1".parse().unwrap();
        let slla = [0xaau8, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let want = wrex_io::ndp::build_ns_frame(iface_mac, src, target, slla);

        let mut r = wrex_core::Registry::empty();
        register(&mut r);
        let sn = wrex_io::ndp::solicited_node(target);
        let mut ef = std::collections::BTreeMap::new();
        ef.insert("src".to_string(), Value::Mac(iface_mac));
        ef.insert(
            "dst".to_string(),
            Value::Mac(wrex_io::ndp::multicast_mac(sn)),
        );
        let mut ipf = std::collections::BTreeMap::new();
        ipf.insert("src".to_string(), Value::Ipv6(src));
        ipf.insert("dst".to_string(), Value::Ipv6(sn));
        ipf.insert("hop_limit".to_string(), Value::Int(255));
        let mut nf = std::collections::BTreeMap::new();
        nf.insert("type".to_string(), Value::Int(135));
        nf.insert("ndp.target".to_string(), Value::Ipv6(target));
        nf.insert(
            "options".to_string(),
            Value::Str(format!("slla:{}", mac_str(slla))),
        );
        let spec = wrex_core::spec::PacketSpec::new(
            vec![
                wrex_core::spec::LayerSpec::with_fields("eth", ef),
                wrex_core::spec::LayerSpec::with_fields(wrex_proto_ip6::KIND, ipf),
                wrex_core::spec::LayerSpec::with_fields(KIND, nf),
            ],
            None,
        );
        let enc = encode(
            &r,
            &spec,
            &wrex_core::encode::EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            &enc.bytes[..],
            &want[..],
            "the codec craft and the driver hand-roll must agree byte-for-byte"
        );
    }

    fn mac_str(m: [u8; 6]) -> String {
        m.iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":")
    }

    #[test]
    fn ndp_options_grammar_roundtrip() {
        let mut r = wrex_core::Registry::empty();
        register(&mut r);
        let mut ns = std::collections::BTreeMap::new();
        ns.insert("type".to_string(), Value::Int(135));
        ns.insert(
            "ndp.target".to_string(),
            Value::Ipv6("fe80::1".parse().unwrap()),
        );
        ns.insert(
            "options".to_string(),
            Value::Str(
                "slla:00:11:22:33:44:55, tlla:aa:bb:cc:dd:ee:ff, mtu:1500, prefix:64,2001:db8::1,3600,1800,l,a, raw:9:0102".into(),
            ),
        );
        let spec = wrex_core::spec::PacketSpec::new(
            vec![
                wrex_core::spec::LayerSpec::new(wrex_proto_ip6::KIND),
                wrex_core::spec::LayerSpec::with_fields(KIND, ns),
            ],
            None,
        );
        let enc = encode(
            &r,
            &spec,
            &wrex_core::encode::EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        let p = wrex_core::dissect::dissect(&r, &enc.bytes, wrex_proto_ip6::KIND);
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        let f = &p.layers[1].fields;
        assert_eq!(f.get("opt.0.type"), Some(&Value::Int(1)));
        assert_eq!(
            f.get("opt.0.addr"),
            Some(&Value::Mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        );
        assert_eq!(f.get("opt.1.type"), Some(&Value::Int(2)));
        assert_eq!(f.get("opt.2.mtu"), Some(&Value::Int(1500)));
        assert_eq!(f.get("opt.3.type"), Some(&Value::Int(3)));
        assert_eq!(f.get("opt.3.prefix_len"), Some(&Value::Int(64)));
        assert_eq!(
            f.get("opt.3.prefix"),
            Some(&Value::Ipv6("2001:db8::1".parse().unwrap()))
        );
        assert_eq!(f.get("opt.3.valid"), Some(&Value::Int(3600)));
        assert_eq!(f.get("opt.3.preferred"), Some(&Value::Int(1800)));
        assert_eq!(
            f.get("opt.3.flags"),
            Some(&Value::List(vec![
                Value::Str("l".into()),
                Value::Str("a".into())
            ]))
        );
        assert_eq!(f.get("opt.4.type"), Some(&Value::Int(9)));
        // Options on a non-NDP type: the pointed error.
        let mut echo = std::collections::BTreeMap::new();
        echo.insert("type".to_string(), Value::Int(128));
        echo.insert(
            "options".to_string(),
            Value::Str("slla:00:11:22:33:44:55".into()),
        );
        let bad = encode(
            &r,
            &wrex_core::spec::PacketSpec::new(
                vec![wrex_core::spec::LayerSpec::with_fields(KIND, echo)],
                None,
            ),
            &wrex_core::encode::EncodeOpts::default(),
        );
        assert!(bad.is_err(), "options must not follow an echo body");
    }

    #[test]
    fn echo_request_golden() {
        let enc = encode(
            &registry(),
            &PacketSpec::new(
                vec![icmp6_spec(&[("echo.id", "4242"), ("echo.seq", "7")])],
                None,
            ),
            &lo6_opts(),
        )
        .unwrap();
        assert_eq!(enc.bytes[..2], [128, 0]);
        assert_eq!(u16::from_be_bytes([enc.bytes[4], enc.bytes[5]]), 4242);
        assert_eq!(u16::from_be_bytes([enc.bytes[6], enc.bytes[7]]), 7);
        // checksum over pseudo + message (ck field zeroed inside msg)
        let mut zeroed = enc.bytes.to_vec();
        zeroed[2] = 0;
        zeroed[3] = 0;
        assert_eq!(
            u16::from_be_bytes([enc.bytes[2], enc.bytes[3]]),
            checksum_over(&zeroed)
        );
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "icmpv6");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.layers[0].fields.get("echo.id"), Some(&Value::Int(4242)));
    }

    #[test]
    fn ndp_shapes() {
        // RS: header only
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![icmp6_spec(&[("type", "133")])], None),
            &lo6_opts(),
        )
        .unwrap();
        assert_eq!(enc.bytes.len(), 8);
        // RA: 16 bytes, fields land
        let enc = encode(
            &registry(),
            &PacketSpec::new(
                vec![icmp6_spec(&[
                    ("type", "134"),
                    ("ndp.cur_hop_limit", "64"),
                    ("ndp.ra_flags", "m,o"),
                    ("ndp.router_lifetime", "1800"),
                    ("ndp.reachable_time", "0x1000"),
                    ("ndp.retrans_timer", "1000"),
                ])],
                None,
            ),
            &lo6_opts(),
        )
        .unwrap();
        assert_eq!(enc.bytes.len(), 16);
        assert_eq!(enc.bytes[4], 64);
        assert_eq!(enc.bytes[5], 0xc0); // m|o
        assert_eq!(u16::from_be_bytes([enc.bytes[6], enc.bytes[7]]), 1800);
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "icmpv6");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(
            p.layers[0].fields.get("ndp.ra_flags"),
            Some(&Value::List(vec![
                Value::Str("m".into()),
                Value::Str("o".into())
            ]))
        );
        // NS: 24 bytes, target + slla option dissects into opt.0.addr
        let mut fields = BTreeMap::new();
        fields.insert("type".to_string(), Value::Int(135));
        fields.insert(
            "ndp.target".to_string(),
            Value::Ipv6("2001:db8::1".parse().unwrap()),
        );
        let spec = LayerSpec::with_fields("icmpv6", fields);
        // SLLA option TLV: type 1, len 1 (one 8-byte unit), 6-byte mac
        // (the unit's last 2 bytes pad).
        let payload = Value::Bytes(Bytes::from(vec![1, 1, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]));
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], Some(payload)),
            &lo6_opts(),
        )
        .unwrap();
        assert_eq!(enc.bytes.len(), 24 + 8);
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "icmpv6");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.layers[0].fields.get("opt.0.type"), Some(&Value::Int(1)));
        assert_eq!(
            p.layers[0].fields.get("opt.0.addr"),
            Some(&Value::Mac([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]))
        );
        assert_eq!(
            p.layers[0].fields.get("ndp.target"),
            Some(&Value::Ipv6("2001:db8::1".parse().unwrap()))
        );
        // payload past the option is empty
        assert!(p.payload.is_empty());
    }

    #[test]
    fn na_flags_and_target() {
        let mut fields = BTreeMap::new();
        fields.insert("type".to_string(), Value::Int(136));
        fields.insert("ndp.na_flags".to_string(), Value::Int(0b100)); // r (aggregate bit 2)
        fields.insert(
            "ndp.target".to_string(),
            Value::Ipv6("fe80::1".parse().unwrap()),
        );
        let spec = LayerSpec::with_fields("icmpv6", fields);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo6_opts()).unwrap();
        assert_eq!(enc.bytes[4], 0x80);
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "icmpv6");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(
            p.layers[0].fields.get("ndp.na_flags"),
            Some(&Value::List(vec![Value::Str("r".into())]))
        );
    }

    #[test]
    fn generic_rest_bytes() {
        let enc = encode(
            &registry(),
            &PacketSpec::new(
                vec![icmp6_spec(&[("type", "1"), ("rest", "hex:01020304")])],
                None,
            ),
            &lo6_opts(),
        )
        .unwrap();
        assert_eq!(&enc.bytes[4..8], &[1, 2, 3, 4]);
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "icmpv6");
        match p.layers[0].fields.get("rest") {
            Some(Value::Bytes(b)) => assert_eq!(&b[..], &[1, 2, 3, 4]),
            other => panic!("rest: {other:?}"),
        }
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
    }

    #[test]
    fn checksum_mismatch_anomaly() {
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![icmp6_spec(&[])], None),
            &lo6_opts(),
        )
        .unwrap();
        let mut bad = enc.bytes.to_vec();
        bad[2] ^= 0xff;
        // Verify needs the v6 parent facts (dissect alone never seeds them).
        let mut ctx = DecodeCtx::new(0);
        ctx.facts.net = lo6_opts().facts.net;
        let _ = CODEC.read(&bad, &mut ctx);
        assert!(
            ctx.anomalies.iter().any(|a| a.path == "icmpv6.checksum"),
            "{:?}",
            ctx.anomalies
        );
    }

    #[test]
    fn truncation() {
        let mut ctx = DecodeCtx::new(0);
        assert!(matches!(
            CODEC.read(&[128, 0, 0, 0], &mut ctx),
            ReadOutcome::Anomaly(DecodeError::Truncated { kind: "icmpv6", .. }, _)
        ));
        // NS needs 24
        let mut ctx = DecodeCtx::new(0);
        let mut ns = vec![135u8, 0, 0, 0, 0, 0, 0, 0];
        ns.extend_from_slice(&[0u8; 15]);
        assert!(matches!(
            CODEC.read(&ns, &mut ctx),
            ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: "icmpv6",
                    need: 24,
                    ..
                },
                _
            )
        ));
    }
}
