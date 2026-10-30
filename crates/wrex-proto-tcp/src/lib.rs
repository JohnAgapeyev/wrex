#![forbid(unsafe_code)]
//! wrex TCP codec (sport/dport/seq/ack/data_offset/flags/window/checksum/
//! urgent/options; rank 30, parent ipv4). Flags expose the aggregate
//! (`tcp.flags`) and per-bit subpaths (`tcp.flags.syn`).

mod options;

use bytes::{BufMut, Bytes};
use std::borrow::Cow;

use wrex_core::dissect::{FieldSpan, LayerView};
use wrex_core::encode::{EncodeCtx, Patch, flagset_or_default, int_or_default};
use wrex_core::error::DecodeError;
use wrex_core::schema::{
    ChecksumEnd, ChecksumStart, Derived, FieldKind, FieldSchema, LayerSchema, Layout, PseudoSource,
    RecordSchema,
};
use wrex_core::spec::LayerSpec;
use wrex_core::value::Value;
use wrex_core::{Anomaly, Codec, DecodeCtx, EncodeError, Next, ReadOutcome};

static FLAGS: &[&str] = &["cwr", "ece", "urg", "ack", "psh", "rst", "syn", "fin"];

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

static FIELDS: [FieldSchema; 10] = [
    d("sport", FieldKind::U16, "source port", Value::Int(0)),
    d("dport", FieldKind::U16, "destination port", Value::Int(0)),
    d("seq", FieldKind::U32, "sequence number", Value::Int(0)),
    d(
        "ack",
        FieldKind::U32,
        "acknowledgment number",
        Value::Int(0),
    ),
    d(
        "data_off",
        FieldKind::U8,
        "data offset in 32-bit words (autofill: derived)",
        Value::Int(0),
    ),
    FieldSchema {
        name: "flags",
        kind: FieldKind::FlagSet,
        bit_names: FLAGS,
        default: Value::Int(0),
        required: false,
        doc: "flag aggregate [cwr,ece,urg,ack,psh,rst,syn,fin]; subpaths flags.<bit>",
    },
    d(
        "window",
        FieldKind::U16,
        "window (autofill: 64240)",
        Value::Int(64240),
    ),
    d(
        "checksum",
        FieldKind::U16,
        "checksum over pseudo-header+segment (autofill: computed)",
        Value::Int(0),
    ),
    d("urgent", FieldKind::U16, "urgent pointer", Value::Int(0)),
    FieldSchema {
        name: "options",
        kind: FieldKind::Bytes,
        bit_names: &[],
        default: Value::Bytes(Bytes::new()),
        required: false,
        doc: "options: eol,nop,mss:1460,ws:7,sackok,sack:L,R,…, or hex:… (mutually exclusive with the opt.N.* record paths)",
    },
];

/// Tranche 22a: the settable `opt` record section — one record per
/// wire option, the `max: None` bound riding index-0 flags
/// (`--tcp-opt-0-mss`, the dns `an.0.*` precedent).
static OPT_FIELDS: [FieldSchema; 8] = [
    d(
        "kind",
        FieldKind::Str,
        "option kind: eol|nop|mss|ws|sackok|sack|ts|mptcp|tfo or a bare number (required per record)",
        Value::Str(Cow::Borrowed("")),
    ),
    d(
        "len",
        FieldKind::U8,
        "option length in bytes incl. kind+len (autofill: derived from the value; explicit kept verbatim — eol/nop carry no length byte)",
        Value::Int(0),
    ),
    d(
        "mss",
        FieldKind::U16,
        "max segment size (kind mss, 0..65535)",
        Value::Int(0),
    ),
    d(
        "ws",
        FieldKind::U8,
        "window scale shift (kind ws, 0..14)",
        Value::Int(0),
    ),
    d(
        "sack",
        FieldKind::Str,
        "sack blocks as L,R,… relative sequence numbers (kind sack)",
        Value::Str(Cow::Borrowed("")),
    ),
    d(
        "ts_val",
        FieldKind::U32,
        "timestamp value (kind ts)",
        Value::Int(0),
    ),
    d(
        "ts_ecr",
        FieldKind::U32,
        "timestamp echo reply (kind ts)",
        Value::Int(0),
    ),
    d(
        "raw",
        FieldKind::Bytes,
        "raw option data after kind+len (tfo/mptcp/unknown kinds — the wire truth)",
        Value::Bytes(Bytes::new()),
    ),
];

static RECORDS: [RecordSchema; 1] = [RecordSchema {
    name: "opt",
    fields: &OPT_FIELDS,
    settable: true,
    max: None,
    doc: "TCP options (RFC 9293 §3.1 + the common extensions): one record per option, crafted through index paths opt.0.*, … (the dns an.0.* precedent; deeper indices ride the spec JSON). Typed fields per kind — mss/ws/sack/ts_val/ts_ecr — raw covers tfo/mptcp/unknown kinds; len autofills from the value (explicit kept verbatim, the deliberate-invalid rule). Dissect-side the wire truth; eol ends the walk, padding after it stays in the options region.",
}];

/// The kind string this codec implements (ADR 3): the vocabulary is
/// compile-checked and symmetric across codecs.
pub const KIND: &str = "tcp";

pub static SCHEMA: LayerSchema = LayerSchema {
    kind: KIND,
    rank: 30,
    parents: &[
        wrex_proto_ip::KIND,
        wrex_proto_ip6::KIND,
        // Tranche 17a: the stackable v6 ext headers (esp/nonext are
        // terminal — nothing stacks on them).
        wrex_proto_ip6ext::KIND_HOPOPTS,
        wrex_proto_ip6ext::KIND_ROUTING,
        wrex_proto_ip6ext::KIND_FRAG,
        wrex_proto_ip6ext::KIND_DSTOPTS,
        wrex_proto_ip6ext::KIND_AH,
    ],
    doc: "TCP (RFC 9293): 20-byte fixed header plus options. data_off autofilled from options length (explicit wins; <5 kept, flagged only under --strict). flags aggregate settable as bit names (syn,ack,...) or raw int; per-bit subpaths --tcp-flags-syn exist. checksum over the pseudo-header (v4 RFC 9293 / v6 RFC 8200 §8.1, family follows the network-layer parent) plus segment and payload. options grammar: eol,nop,mss:1460,ws:7,sackok,sack:L,R,..., or hex:BYTES — or the settable opt.N.* record paths (tranche 22a: --tcp-opt-0-kind mss --tcp-opt-0-mss 1460, one record per option, the dns an.0.* precedent; mutually exclusive with the grammar).",
    fields: &FIELDS,
    records: &RECORDS,
};

/// TCP codec unit. Register via [`register`] (the ADR-3 closure);
/// bespoke registries may use `&wrex_proto_tcp::CODEC` directly.
pub struct TcpCodec;

pub static CODEC: TcpCodec = TcpCodec;

/// ADR 3 registration closure: register self (dedup-guarded via
/// [`Registry::get`]), then the parent crates'. Self-first keeps
/// `standard()`'s fixed registration order byte-identical —
/// presence, not order, is the guarantee.
pub fn register(r: &mut wrex_core::Registry) {
    if r.get(KIND).is_none() {
        r.register(&CODEC);
    }
    wrex_proto_ip::register(r);
    wrex_proto_ip6::register(r);
    // Tranche 17a: the ext family is a parent now (tcp stacks on the
    // five non-terminal kinds — ADR 3: parents are deps).
    wrex_proto_ip6ext::register(r);
}

/// The `opt.N.sack` value → wire: 4-byte BE relative blocks.
fn sack_wire(n: usize, raw: &str) -> Result<Vec<u8>, EncodeError> {
    let nums: Vec<u32> = if raw.trim().is_empty() {
        Vec::new()
    } else {
        raw.split(',')
            .map(|s| s.trim().parse::<u32>())
            .collect::<Result<_, _>>()
            .map_err(|_| EncodeError::IncompatibleStack {
                detail: format!("tcp.opt.{n}.sack needs L,R,… in `{raw}`"),
            })?
    };
    if nums.is_empty() {
        return Err(EncodeError::IncompatibleStack {
            detail: format!("tcp.opt.{n}.sack needs at least one value"),
        });
    }
    let mut out = Vec::with_capacity(nums.len() * 4);
    for v in &nums {
        out.extend_from_slice(&v.to_be_bytes());
    }
    Ok(out)
}

/// Tranche 22a: ONE `opt.N.*` record → wire bytes (the dns
/// `crafted_records` pattern — the kind is required, the typed value
/// fields default, explicit `len` wins verbatim).
fn opt_record_bytes(spec: &LayerSpec, n: usize) -> Result<Vec<u8>, EncodeError> {
    let bad = |detail: String| EncodeError::IncompatibleStack { detail };
    let int = |name: &str, default: u128| -> u128 {
        let key = format!("opt.{n}.{name}");
        match spec.fields.get(key.as_str()) {
            Some(Value::Int(v)) => *v,
            // Non-int on an int field: the default (the flat-field value
            // grammar rejects it upstream).
            _ => default,
        }
    };
    let bytes_of = |name: &str| -> Option<Vec<u8>> {
        let key = format!("opt.{n}.{name}");
        match spec.fields.get(key.as_str()) {
            Some(Value::Bytes(b)) => Some(b.to_vec()),
            _ => None,
        }
    };
    let str_of = |name: &str| -> Option<String> {
        let key = format!("opt.{n}.{name}");
        match spec.fields.get(key.as_str()) {
            Some(Value::Str(s)) => Some(s.to_string()),
            _ => None,
        }
    };
    let kind_key = format!("opt.{n}.kind");
    let Some(Value::Str(kind)) = spec.fields.get(kind_key.as_str()) else {
        return Err(EncodeError::Unfillable {
            field: format!("tcp.opt.{n}.kind"),
        });
    };
    let code = options::parse_kind(kind)
        .ok_or_else(|| bad(format!("tcp.opt.{n}.kind: unknown option kind `{kind}`")))?;
    let mut out = match code {
        0 => vec![options::OPT_EOL],
        1 => vec![options::OPT_NOP],
        2 => {
            let mss = int("mss", 0) as u16;
            vec![options::OPT_MSS, 4, (mss >> 8) as u8, mss as u8]
        }
        3 => vec![options::OPT_WS, 3, int("ws", 0) as u8, options::OPT_NOP],
        4 => vec![options::OPT_SACKOK, 2, options::OPT_NOP, options::OPT_NOP],
        5 => {
            let raw = sack_wire(n, str_of("sack").as_deref().unwrap_or(""))?;
            let mut out = vec![options::OPT_SACK, (2 + raw.len()) as u8];
            out.extend_from_slice(&raw);
            out
        }
        8 => {
            let val = int("ts_val", 0) as u32;
            let ecr = int("ts_ecr", 0) as u32;
            let mut out = vec![options::OPT_TS, 10];
            out.extend_from_slice(&val.to_be_bytes());
            out.extend_from_slice(&ecr.to_be_bytes());
            out
        }
        // tfo/mptcp/unknown kinds: `raw` is the data (the wire truth).
        _ => {
            let data = bytes_of("raw").unwrap_or_default();
            if data.len() > 253 {
                return Err(bad(format!(
                    "tcp.opt.{n}.raw: {} bytes exceeds the 253-byte option data maximum",
                    data.len()
                )));
            }
            let mut out = Vec::with_capacity(2 + data.len());
            out.push(code);
            out.push((2 + data.len()) as u8);
            out.extend_from_slice(&data);
            out
        }
    };
    // Explicit len wins verbatim (the craft rule — kept unvalidated,
    // flagged only under --strict semantics at the patch layer).
    let len_key = format!("opt.{n}.len");
    if let Some(Value::Int(v)) = spec.fields.get(len_key.as_str()) {
        if out.len() < 2 {
            return Err(bad(format!(
                "tcp.opt.{n}.len: `{}` carries no length byte",
                options::render_kind(code)
            )));
        }
        out[1] = *v as u8;
    }
    Ok(out)
}

/// Options bytes for a spec: the `Value::Str` list grammar or raw
/// `Value::Bytes` (mutually exclusive with the `opt.N.*` record
/// paths — the dhcp msg_type precedent), zero-padded to the 4-byte
/// grid by the caller.
fn options_region(spec: &LayerSpec) -> Result<Vec<u8>, EncodeError> {
    let mut records = Vec::new();
    for n in 0usize.. {
        let prefix = format!("opt.{n}.");
        if !spec.fields.keys().any(|k| k.starts_with(&prefix)) {
            break;
        }
        records.extend(opt_record_bytes(spec, n)?);
    }
    let raw = match spec.fields.get("options") {
        Some(Value::Str(s)) => options::parse_options(s)?,
        Some(Value::Bytes(b)) => b.to_vec(),
        _ => Vec::new(),
    };
    if !records.is_empty() && !raw.is_empty() {
        return Err(EncodeError::IncompatibleStack {
            detail: "tcp.options and opt.N.* records are mutually exclusive".to_string(),
        });
    }
    let mut raw = if records.is_empty() { raw } else { records };
    raw.extend(std::iter::repeat_n(0u8, options::pad_len(raw.len())));
    Ok(raw)
}

impl Codec for TcpCodec {
    fn schema(&self) -> &'static LayerSchema {
        &SCHEMA
    }

    fn header_len(&self, spec: &LayerSpec) -> Result<usize, EncodeError> {
        Ok(20 + options_region(spec)?.len())
    }

    fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
        let af = ctx.autofill;
        let start = ctx.buf.len();
        let opts = options_region(spec)?;
        ctx.buf.put_u16(int_or_default(spec, &FIELDS[0], af) as u16);
        ctx.buf.put_u16(int_or_default(spec, &FIELDS[1], af) as u16);
        ctx.buf.put_u32(int_or_default(spec, &FIELDS[2], af) as u32);
        ctx.buf.put_u32(int_or_default(spec, &FIELDS[3], af) as u32);
        let at_doff = ctx.buf.len();
        let doff_explicit = spec.fields.contains_key("data_off");
        let doff = if doff_explicit {
            (int_or_default(spec, &FIELDS[4], af) as u8 & 0x0f) << 4
        } else {
            ((5 + opts.len() / 4) as u8) << 4
        };
        ctx.buf.put_u8(doff);
        ctx.defer(Patch::MinByte {
            at: at_doff,
            min: 0x50,
            path: "tcp.data_off",
        });
        let flags = flagset_or_default(spec, &FIELDS[5], af) as u8;
        ctx.buf.put_u8(flags);
        ctx.buf.put_u16(int_or_default(spec, &FIELDS[6], af) as u16); // window
        let at_ck = ctx.buf.len();
        let ck_explicit = spec.fields.contains_key("checksum");
        if let Some(Value::Int(v)) = spec.fields.get("checksum") {
            ctx.buf.put_u16(*v as u16);
        } else {
            ctx.buf.put_u16(0); // checksum placeholder
        }
        ctx.buf.put_u16(int_or_default(spec, &FIELDS[8], af) as u16); // urgent
        ctx.buf.extend_from_slice(&opts);
        let pseudo = ctx.facts.net.map(|n| wrex_core::encode::l4_pseudo(n, 6));
        // The pseudo-header length is the L4 message length — the
        // upper-layer packet EXCLUDES any v6 extension headers (RFC
        // 8200 §8.1 as every real stack implements it; the HP3-b
        // foreign-capture corpus caught the ext-inclusive T17a fold).
        // The fold starts at this layer's own header.
        let ck_start = start;
        ctx.defer(Patch::Checksum {
            at: at_ck,
            start: ck_start,
            end: None,
            pseudo,
            explicit: ck_explicit,
            path: "tcp.checksum",
        });
        Ok(())
    }

    fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
        if bytes.is_empty() {
            return ReadOutcome::Empty;
        }
        if bytes.len() < 20 {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: "tcp",
                    need: 20,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let doff = bytes[12] >> 4;
        if doff < 5 {
            ctx.anomalies.push(Anomaly::new("tcp.data_off", "below 5"));
            return ReadOutcome::Anomaly(
                DecodeError::BadField {
                    path: "tcp.data_off".into(),
                    reason: format!("data offset {doff} below 5"),
                },
                Next::Payload,
            );
        }
        let hlen = doff as usize * 4;
        if bytes.len() < hlen {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: "tcp",
                    need: hlen,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let sport = u16::from_be_bytes([bytes[0], bytes[1]]);
        let dport = u16::from_be_bytes([bytes[2], bytes[3]]);
        let seq = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let ack = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let flags_byte = bytes[13];
        let window = u16::from_be_bytes([bytes[14], bytes[15]]);
        let found_ck = u16::from_be_bytes([bytes[16], bytes[17]]);
        let urgent = u16::from_be_bytes([bytes[18], bytes[19]]);

        // Checksum verify (non-fatal): pseudo-header (family follows the
        // network-layer parent) + the upper-layer packet (tranche 17a:
        // v6 ext headers included, RFC 8200 §8.1), ck zeroed. With the
        // engine's frame lookback + a recorded upper_start the range
        // starts at the first ext header; the legacy `bytes` slice
        // otherwise (identical on ext-free stacks).
        // SKIPPED on a fragment carrier: the pseudo-header length covers
        // the ORIGINAL unfragmented packet — a single fragment can
        // never verify (the HP3-b foreign-fragment corpus drove the
        // skip; the reassembled datagram verifies instead).
        if let (Some(net), false) = (ctx.facts.net, ctx.facts.fragmented) {
            // The fold covers the L4 message only (the pseudo length is
            // bytes.len(); the data starts at this layer — ext headers
            // excluded, the kernel/interop reading of RFC 8200 §8.1).
            let mut acc = wrex_core::ChecksumAccumulator::new();
            wrex_core::encode::l4_pseudo(net, 6).accumulate_into(&mut acc, bytes.len());
            acc.add_bytes(&bytes[..16]);
            acc.add_u16(0);
            acc.add_bytes(&bytes[18..]);
            let computed = acc.value();
            if found_ck != computed {
                ctx.anomalies.push(Anomaly::new(
                    "tcp.checksum",
                    format!("mismatch (computed 0x{computed:04x}, found 0x{found_ck:04x})"),
                ));
            }
        }

        // Flag names for the aggregate (MSB-first bit_names).
        let mut names: Vec<Value> = Vec::new();
        for (i, name) in FLAGS.iter().enumerate() {
            if flags_byte & (1 << (7 - i)) != 0 {
                names.push(Value::Str((*name).into()));
            }
        }

        let mut fields = std::collections::BTreeMap::new();
        fields.insert("sport".into(), Value::Int(sport as u128));
        fields.insert("dport".into(), Value::Int(dport as u128));
        fields.insert("seq".into(), Value::Int(seq as u128));
        fields.insert("ack".into(), Value::Int(ack as u128));
        fields.insert("data_off".into(), Value::Int(doff as u128));
        fields.insert("flags".into(), Value::List(names));
        fields.insert("window".into(), Value::Int(window as u128));
        fields.insert("checksum".into(), Value::Int(found_ck as u128));
        fields.insert("urgent".into(), Value::Int(urgent as u128));
        fields.insert(
            "options".into(),
            Value::Bytes(Bytes::copy_from_slice(&bytes[20..hlen])),
        );

        // Tranche 22a: the typed `opt.N.*` record walk over the options
        // region (the dhcp pattern — parse-time spans, the flat
        // `options` field keeps the raw region). EOL ends the walk
        // (padding after it stays in `options`); a malformed option
        // stops with a never-fatal anomaly, the rest stays raw. The
        // walk consumes a shrinking slice (no running cursor: a
        // mutated advance cannot hang — the kill-strength rule).
        let region = &bytes[20..hlen];
        let mut spans: std::collections::BTreeMap<Cow<'static, str>, FieldSpan> =
            std::collections::BTreeMap::new();
        let rbase = ctx.offset + 20;
        let mut rest = region;
        let mut i = 0usize;
        while !rest.is_empty() {
            let consumed = region.len() - rest.len();
            let kind = rest[0];
            let kat = rbase + consumed;
            spans.insert(
                format!("opt.{i}.kind").into(),
                FieldSpan::Bytes(kat..kat + 1),
            );
            if kind == 0 {
                fields.insert(format!("opt.{i}.kind").into(), Value::Str("eol".into()));
                break;
            }
            if kind == 1 {
                fields.insert(format!("opt.{i}.kind").into(), Value::Str("nop".into()));
                rest = &rest[1..];
                i += 1;
                continue;
            }
            let Some(&len_b) = rest.get(1) else {
                ctx.anomalies.push(Anomaly::new(
                    format!("tcp.opt.{i}"),
                    "option header overruns the region",
                ));
                break;
            };
            let olen = len_b as usize;
            if olen < 2 {
                ctx.anomalies.push(Anomaly::new(
                    format!("tcp.opt.{i}"),
                    format!("option length {olen} below 2"),
                ));
                break;
            }
            if olen > rest.len() {
                ctx.anomalies.push(Anomaly::new(
                    format!("tcp.opt.{i}"),
                    format!("option overruns the header (kind {kind}, needs {olen} bytes)"),
                ));
                break;
            }
            let data = &rest[2..olen];
            let dat = kat + 2;
            spans.insert(
                format!("opt.{i}.len").into(),
                FieldSpan::Bytes(kat + 1..kat + 2),
            );
            spans.insert(
                format!("opt.{i}.raw").into(),
                FieldSpan::Bytes(dat..dat + data.len()),
            );
            fields.insert(
                format!("opt.{i}.kind").into(),
                Value::Str(options::render_kind(kind)),
            );
            fields.insert(format!("opt.{i}.len").into(), Value::Int(olen as u128));
            fields.insert(
                format!("opt.{i}.raw").into(),
                Value::Bytes(Bytes::copy_from_slice(data)),
            );
            // Typed values per kind (never fatal on bad shapes — the
            // dhcp rule: the guard simply does not fire, `raw` covers).
            match kind {
                2 if olen == 4 => {
                    spans.insert(
                        format!("opt.{i}.mss").into(),
                        FieldSpan::Bytes(dat..dat + 2),
                    );
                    fields.insert(
                        format!("opt.{i}.mss").into(),
                        Value::Int(u16::from_be_bytes([data[0], data[1]]) as u128),
                    );
                }
                3 if olen == 3 => {
                    spans.insert(format!("opt.{i}.ws").into(), FieldSpan::Bytes(dat..dat + 1));
                    fields.insert(format!("opt.{i}.ws").into(), Value::Int(data[0] as u128));
                }
                5 if data.len().is_multiple_of(4) && data.len() >= 4 => {
                    // SACK blocks: 4-byte BE relative edges, comma-joined.
                    let blocks: Vec<String> = data
                        .as_chunks::<4>()
                        .0
                        .iter()
                        .map(|c| u32::from_be_bytes(*c).to_string())
                        .collect();
                    spans.insert(
                        format!("opt.{i}.sack").into(),
                        FieldSpan::Bytes(dat..dat + data.len()),
                    );
                    fields.insert(
                        format!("opt.{i}.sack").into(),
                        Value::Str(blocks.join(",").into()),
                    );
                }
                8 if olen == 10 => {
                    spans.insert(
                        format!("opt.{i}.ts_val").into(),
                        FieldSpan::Bytes(dat..dat + 4),
                    );
                    spans.insert(
                        format!("opt.{i}.ts_ecr").into(),
                        FieldSpan::Bytes(dat + 4..dat + 8),
                    );
                    fields.insert(
                        format!("opt.{i}.ts_val").into(),
                        Value::Int(u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u128),
                    );
                    fields.insert(
                        format!("opt.{i}.ts_ecr").into(),
                        Value::Int(u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as u128),
                    );
                }
                // sackok (4): the kind carries it; tfo (34)/mptcp (30)/
                // unknown kinds: `raw` is the wire truth.
                _ => {}
            }
            i += 1;
            rest = &rest[olen..];
        }

        let view = LayerView {
            kind: "tcp",
            span: ctx.offset..ctx.offset + hlen,
            field_spans: spans,
            fields,
        };
        // TCP is terminal (the payload follows).
        ReadOutcome::Layer(view, Some(Next::Payload))
    }

    /// Tranche 11b fixed layouts (base 20 bytes; data_off is the top
    /// nibble of byte 12; `options` is dynamic → None).
    fn layouts(&self) -> &'static [(&'static str, Layout)] {
        &[
            ("sport", Layout::Bytes { at: 0, len: 2 }),
            ("dport", Layout::Bytes { at: 2, len: 2 }),
            ("seq", Layout::Bytes { at: 4, len: 4 }),
            ("ack", Layout::Bytes { at: 8, len: 4 }),
            (
                "data_off",
                Layout::Bits {
                    at: 12,
                    shift: 0,
                    width: 4,
                },
            ),
            ("flags", Layout::Bytes { at: 13, len: 1 }),
            ("window", Layout::Bytes { at: 14, len: 2 }),
            ("checksum", Layout::Bytes { at: 16, len: 2 }),
            ("urgent", Layout::Bytes { at: 18, len: 2 }),
        ]
    }

    /// `checksum` covers the segment to the frame end over the
    /// pseudo-header from the net facts (family follows the parent).
    fn derived(&self) -> &'static [Derived] {
        &[Derived::Checksum {
            field: "checksum",
            at: 16,
            start: ChecksumStart::UpperPacket,
            end: ChecksumEnd::Frame,
            pseudo: PseudoSource::FromFacts,
        }]
    }
}

#[cfg(feature = "test-util")]
pub mod strategy {
    //! proptest strategies for `LayerSpec` (behind `test-util`).
    use proptest::prelude::*;
    use wrex_core::spec::LayerSpec;
    use wrex_core::value::Value;

    /// Valid tcp specs: any numeric fields, any flag mask, valid options.
    /// Tranche 22a: the `opt` record section samples too — one random
    /// valid record shape (G1: every settable record field randomized;
    /// `len` is the recorded autofill exemption).
    pub fn strategy() -> BoxedStrategy<LayerSpec> {
        let flags = any::<u8>().prop_map(|v| Value::Int(v as u128));
        let opts = proptest::option::of(proptest::sample::select(vec![
            "eol".to_string(),
            "nop,nop".to_string(),
            "mss:1460".to_string(),
            "ws:7".to_string(),
            "sackok".to_string(),
            "sack:1,2".to_string(),
            "hex:01020304".to_string(),
        ]));
        // One record shape per sample; every record field covered
        // across the pool (kind/mss/ws/sack/ts_val/ts_ecr/raw). The
        // value strategies are arithmetic-free (ranges/selects, no
        // `%`/`+` for the kill-strength rule) and the shape dispatch
        // is a plain match the in-crate audit (below) pins per arm.
        let rec = proptest::option::of((
            (0usize..8),
            any::<u16>(),
            (0u8..=14),
            any::<u32>(),
            any::<u32>(),
            proptest::collection::vec(any::<u8>(), 0..=12),
            proptest::sample::select(vec![
                "9".to_string(),
                "14".to_string(),
                "25".to_string(),
                "77".to_string(),
            ]),
        ))
        .prop_map(|opt| {
            opt.map(|(choice, mss, ws, tv, te, raw, unknown)| {
                let mut f = std::collections::BTreeMap::new();
                match choice {
                    0 => {
                        f.insert("kind", Value::Str("mss".into()));
                        f.insert("mss", Value::Int(mss as u128));
                    }
                    1 => {
                        f.insert("kind", Value::Str("ws".into()));
                        f.insert("ws", Value::Int(ws as u128));
                    }
                    2 => {
                        f.insert("kind", Value::Str("sackok".into()));
                    }
                    3 => {
                        f.insert("kind", Value::Str("sack".into()));
                        f.insert("sack", Value::Str(format!("{tv},{te}").into()));
                    }
                    4 => {
                        f.insert("kind", Value::Str("ts".into()));
                        f.insert("ts_val", Value::Int(tv as u128));
                        f.insert("ts_ecr", Value::Int(te as u128));
                    }
                    5 => {
                        f.insert("kind", Value::Str("tfo".into()));
                        f.insert("raw", Value::Bytes(bytes::Bytes::from(raw)));
                    }
                    6 => {
                        // Unknown kind (a select spelling), raw data.
                        f.insert("kind", Value::Str(unknown.into()));
                        f.insert("raw", Value::Bytes(bytes::Bytes::from(raw)));
                    }
                    _ => {
                        f.insert("kind", Value::Str("nop".into()));
                    }
                }
                f
            })
        });
        (
            any::<u16>(),
            any::<u16>(),
            any::<u32>(),
            any::<u32>(),
            flags,
            any::<u16>(),
            any::<u16>(),
            opts,
            rec,
        )
            .prop_map(
                |(sport, dport, seq, ack, flags, window, urgent, opts, rec)| {
                    let mut fields = std::collections::BTreeMap::new();
                    fields.insert("sport".into(), Value::Int(sport as u128));
                    fields.insert("dport".into(), Value::Int(dport as u128));
                    fields.insert("seq".into(), Value::Int(seq as u128));
                    fields.insert("ack".into(), Value::Int(ack as u128));
                    fields.insert("flags".into(), flags);
                    fields.insert("window".into(), Value::Int(window as u128));
                    fields.insert("urgent".into(), Value::Int(urgent as u128));
                    // Records and the grammar are mutually exclusive —
                    // the record wins, the grammar sample stays unset.
                    // (A Some record is never empty: every shape arm
                    // inserts its kind — no emptiness guard to mutate.)
                    match rec {
                        Some(r) => {
                            for (k, v) in r {
                                fields.insert(format!("opt.0.{k}").into(), v);
                            }
                        }
                        None => {
                            if let Some(o) = opts {
                                fields.insert("options".into(), Value::Str(o.into()));
                            }
                        }
                    }
                    LayerSpec::with_fields("tcp", fields)
                },
            )
            .boxed()
    }

    /// In-crate G1 audit (the kill-strength rule: the strategy is
    /// diff-surface now, so its coverage pins live next to it — the
    /// wrex-test audit runs in another crate's suite). Every record
    /// field (len exempt — autofill) sampled ≥8 times in 512 runs,
    /// and every kind spelling appears — a deleted shape arm starves
    /// its fields and fails here.
    #[cfg(test)]
    #[test]
    fn audit_covers_every_record_field() {
        use proptest::prelude::*;
        use proptest::test_runner::TestRunner;
        let mut runner = TestRunner::new(ProptestConfig::default());
        let s = strategy();
        let mut fields: std::collections::BTreeMap<String, usize> = Default::default();
        let mut kinds: Vec<String> = Vec::new();
        for _ in 0..512 {
            let spec = s.new_tree(&mut runner).unwrap().current();
            for (k, v) in &spec.fields {
                // (Guard-continuation style: flat, no `&&` let-chains
                // — every boolean operator is mutatable surface.)
                let Some(name) = k.strip_prefix("opt.0.") else {
                    continue;
                };
                *fields.entry(name.to_string()).or_default() += 1;
                if name != "kind" {
                    continue;
                }
                let Value::Str(kind) = v else {
                    continue;
                };
                if !kinds.iter().any(|k| k == &**kind) {
                    kinds.push(kind.to_string());
                }
            }
        }
        for f in crate::SCHEMA.records[0].fields {
            if f.name == "len" {
                continue; // autofill exemption (the G1 ledger)
            }
            assert!(
                fields.get(f.name).is_some_and(|n| *n >= 8),
                "opt.0.{} sampled {} times in 512 (want >= 8): {:?}",
                f.name,
                fields.get(f.name).unwrap_or(&0),
                fields
            );
        }
        for kind in ["mss", "ws", "sackok", "sack", "ts", "tfo", "nop"] {
            assert!(
                kinds.contains(&kind.to_string()),
                "kind {kind} never sampled: {kinds:?}"
            );
        }
        // the unknown-kind select spellings are bare numbers
        for kind in ["9", "14", "25", "77"] {
            assert!(
                kinds.contains(&kind.to_string()),
                "unknown kind {kind} never sampled: {kinds:?}"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    /// Schema invariant (const-eval pass): no duplicate field names in
    /// the table. `field_names_unique` is a const fn, but the table is a
    /// static (`Bytes` interior mutability blocks const eval), so the
    /// proof runs here instead of in a `const _`.
    #[test]
    fn schema_field_names_unique() {
        assert!(wrex_core::schema::field_names_unique(super::SCHEMA.fields));
    }

    /// Schema invariant (const-eval pass): no duplicate field names in
    /// any table — `field_names_unique` is a const fn, but the tables
    /// are statics (Bytes interior mutability blocks const eval), so
    /// the proof runs here instead.
    use super::*;
    use std::collections::BTreeMap;
    use wrex_core::Registry;
    use wrex_core::dissect::{DecodeCtx, Facts, NetFacts};
    use wrex_core::encode::{EncodeOpts, encode};
    use wrex_core::spec::PacketSpec;
    use wrex_core::value::parse_value;

    fn tcp_spec(fields: &[(&str, &str)]) -> LayerSpec {
        let mut map = BTreeMap::new();
        for (k, v) in fields {
            if *k == "options" {
                map.insert(
                    Cow::Owned(k.to_string()),
                    Value::Str((*v).to_string().into()),
                );
                continue;
            }
            let value = match SCHEMA.resolve(k) {
                Some(wrex_core::ResolvedField::Field(fs)) => parse_value(fs, v).unwrap(),
                Some(wrex_core::ResolvedField::FlagBit { .. }) => {
                    wrex_core::parse_bool(v).map(Value::Bool).unwrap()
                }
                // Tranche 22a: `opt.N.*` record paths parse through
                // their record field schemas.
                Some(wrex_core::ResolvedField::RecordField { field, .. }) => {
                    parse_value(field, v).unwrap()
                }
                None => panic!("no field {k}"),
            };
            map.insert(Cow::Owned(k.to_string()), value);
        }
        LayerSpec::with_fields("tcp", map)
    }

    fn registry() -> Registry {
        let mut r = Registry::empty();
        r.register(&CODEC);
        r
    }

    fn lo_opts() -> EncodeOpts {
        EncodeOpts {
            autofill: true,
            strict: false,
            facts: Facts {
                net: Some(NetFacts::V4 {
                    src: "127.0.0.1".parse().unwrap(),
                    dst: "127.0.0.1".parse().unwrap(),
                    proto: 6,
                }),
                ..Default::default()
            },
        }
    }

    /// ADR 3: ipv4/ipv6 are real parent deps, so this registers the
    /// actual IP codecs through the `register()` closure and dissects
    /// crafted ip→tcp packets end to end, both families — the string
    /// dispatch table can no longer drift from the kinds it names.
    #[test]
    fn ip_dispatches_into_tcp_with_real_codecs() {
        let mut r = wrex_core::Registry::empty();
        register(&mut r);
        for parent in [wrex_proto_ip::KIND, wrex_proto_ip6::KIND] {
            let spec = wrex_core::spec::PacketSpec::new(
                vec![wrex_core::spec::LayerSpec::new(parent), tcp_spec(&[])],
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
            let p = wrex_core::dissect::dissect(&r, &enc.bytes, parent);
            assert_eq!(
                p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
                vec![parent, KIND],
                "{parent} proto/next_header 6 must chain into the real tcp codec"
            );
        }
    }

    /// tcp under a v6 extension chain — [ipv6, hopopts, tcp] crafts
    /// with the checksum covering the L4 message ONLY (RFC 8200 §8.1
    /// as the kernel implements it — the ext bytes excluded; the
    /// HP3-b foreign-capture convention fix) and dissects
    /// anomaly-free through the real codecs.
    #[test]
    fn ext_chain_checksum_covers_hopopts() {
        let mut r = wrex_core::Registry::empty();
        register(&mut r);
        let mut hf = std::collections::BTreeMap::new();
        hf.insert(
            "options".into(),
            wrex_core::Value::Bytes(bytes::Bytes::from_static(&[
                0x01, 0x04, 0x00, 0x00, 0x00, 0x00,
            ])),
        );
        let spec = wrex_core::spec::PacketSpec::new(
            vec![
                wrex_core::spec::LayerSpec::new(wrex_proto_ip6::KIND),
                wrex_core::spec::LayerSpec::with_fields(wrex_proto_ip6ext::KIND_HOPOPTS, hf),
                tcp_spec(&[]),
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
            vec![wrex_proto_ip6::KIND, wrex_proto_ip6ext::KIND_HOPOPTS, "tcp"]
        );
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
    }

    #[test]
    fn header_autofill_defaults() {
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![tcp_spec(&[("flags", "syn")])], None),
            &lo_opts(),
        )
        .unwrap();
        assert_eq!(enc.bytes.len(), 20);
        assert_eq!(enc.bytes[12], 5 << 4); // data_off
        assert_eq!(enc.bytes[13], 0x02); // syn = bit 1
        assert_eq!(u16::from_be_bytes([enc.bytes[14], enc.bytes[15]]), 64240);
    }

    #[test]
    fn per_bit_flag_subpaths() {
        // aggregate + per-bit subpath merge
        let spec = tcp_spec(&[
            ("flags", "syn"),
            ("flags.ack", "true"),
            ("flags.syn", "false"),
        ]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
        // syn set then cleared, ack set: 0x10
        assert_eq!(enc.bytes[13], 0x10);
        let spec2 = tcp_spec(&[("flags", "0")]);
        let enc2 = encode(&registry(), &PacketSpec::new(vec![spec2], None), &lo_opts()).unwrap();
        assert_eq!(enc2.bytes[13], 0);
    }

    #[test]
    fn options_roundtrip() {
        let spec = tcp_spec(&[("options", "nop,mss:1460,ws:7,sackok,sack:1,2,nop")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
        // nop(1) + mss(4) + ws(3→padded to 4) + sackok(2→padded 4) + sack(2+8=10→pad 12?) ...
        // verify by dissection instead of hardcoding: options hex region round-trips
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "tcp");
        match p.layers[0].fields.get("options") {
            Some(Value::Bytes(b)) => assert_eq!(&b[..], &enc.bytes[20..]),
            other => panic!("options: {other:?}"),
        }
        assert_eq!(
            p.layers[0].fields.get("data_off"),
            Some(&Value::Int((enc.bytes.len() / 4) as u128))
        );
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
    }

    #[test]
    fn checksum_covers_payload() {
        let spec = tcp_spec(&[("sport", "1"), ("dport", "2"), ("flags", "syn,ack")]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(
                vec![spec],
                Some(Value::Bytes(bytes::Bytes::from_static(&[0xaa, 0xbb]))),
            ),
            &lo_opts(),
        )
        .unwrap();
        let mut acc = wrex_core::ChecksumAccumulator::new();
        acc.add_ipv4("127.0.0.1".parse().unwrap());
        acc.add_ipv4("127.0.0.1".parse().unwrap());
        acc.add_u16(u16::from_be_bytes([0, 6]));
        acc.add_u16(22);
        acc.add_bytes(&enc.bytes[..16]);
        acc.add_u16(0);
        acc.add_bytes(&enc.bytes[18..]);
        assert_eq!(
            u16::from_be_bytes([enc.bytes[16], enc.bytes[17]]),
            acc.value()
        );
    }

    #[test]
    fn read_flags_names_and_checksum_anomaly() {
        let spec = tcp_spec(&[("flags", "syn,ack"), ("sport", "4444")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "tcp");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        match p.layers[0].fields.get("flags") {
            Some(Value::List(names)) => {
                let got: Vec<&str> = names
                    .iter()
                    .filter_map(|v| match v {
                        Value::Str(s) => Some(&**s),
                        _ => None,
                    })
                    .collect();
                assert_eq!(got, vec!["ack", "syn"]); // sorted
            }
            other => panic!("flags: {other:?}"),
        }
        // corrupt checksum → anomaly via read (verify needs NetFacts)
        let mut bad = enc.bytes.to_vec();
        bad[16] ^= 0xff;
        let mut ctx = DecodeCtx::new(0);
        ctx.facts.net = lo_opts().facts.net;
        let _ = CODEC.read(&bad, &mut ctx);
        assert!(
            ctx.anomalies.iter().any(|a| a.path == "tcp.checksum"),
            "{:?}",
            ctx.anomalies
        );
    }

    #[test]
    fn bad_data_offset_and_truncation() {
        let mut ctx = DecodeCtx::new(0);
        assert!(matches!(
            CODEC.read(&[0u8; 19], &mut ctx),
            ReadOutcome::Anomaly(DecodeError::Truncated { kind: "tcp", .. }, _)
        ));
        // data_off=4 → BadField
        let mut hdr = vec![0u8; 20];
        hdr[12] = 0x40;
        let mut ctx = DecodeCtx::new(0);
        match CODEC.read(&hdr, &mut ctx) {
            ReadOutcome::Anomaly(DecodeError::BadField { path, .. }, _) => {
                assert_eq!(path, "tcp.data_off");
            }
            other => panic!("expected badfield, got {other:?}"),
        }
    }

    // --- tranche 22a: the settable opt record sections -------------------

    /// One record per typed kind → wire golden; the record region
    /// composes with the 4-byte-grid padding (data_off derives).
    #[test]
    fn record_craft_wire_gold() {
        let spec = tcp_spec(&[
            ("opt.0.kind", "mss"),
            ("opt.0.mss", "1460"),
            ("opt.1.kind", "nop"),
            ("opt.2.kind", "ws"),
            ("opt.2.ws", "7"),
            ("opt.3.kind", "sackok"),
            ("opt.4.kind", "sack"),
            ("opt.4.sack", "1,2"),
            ("opt.5.kind", "ts"),
            ("opt.5.ts_val", "0x11223344"),
            ("opt.5.ts_ecr", "7"),
        ]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
        // mss(4) nop(1) ws(4) sackok(4) sack(10) ts(10) = 33 → pad 3 → 36
        assert_eq!(enc.bytes.len(), 20 + 36);
        let want: Vec<u8> = [
            &[0x02u8, 0x04, 0x05, 0xb4][..],                   // mss 1460
            &[0x01],                                           // nop
            &[0x03, 0x03, 0x07, 0x01],                         // ws 7 (nop-padded)
            &[0x04, 0x02, 0x01, 0x01],                         // sackok (nop-padded)
            &[0x05, 0x0a, 0, 0, 0, 1, 0, 0, 0, 2],             // sack 1,2
            &[0x08, 0x0a, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 7], // ts val/ecr
            &[0, 0, 0],                                        // grid padding
        ]
        .concat();
        assert_eq!(&enc.bytes[20..], &want[..]);
        assert_eq!(enc.bytes[12], 14 << 4); // data_off = 5 + 9
        // dissect back: every record typed, no anomalies
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "tcp");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        let fl = &p.layers[0].fields;
        // The ws/sackok records carry nop padding on the wire (len 3 / 2
        // + a nop pad byte) — the pad bytes dissect as their own nop
        // records (the wire truth).
        assert_eq!(
            fl.get("opt.0.kind"),
            Some(&Value::Str(Cow::Borrowed("mss")))
        );
        assert_eq!(fl.get("opt.0.mss"), Some(&Value::Int(1460)));
        assert_eq!(fl.get("opt.0.len"), Some(&Value::Int(4)));
        assert_eq!(
            fl.get("opt.1.kind"),
            Some(&Value::Str(Cow::Borrowed("nop")))
        );
        assert_eq!(fl.get("opt.2.ws"), Some(&Value::Int(7)));
        assert_eq!(
            fl.get("opt.3.kind"),
            Some(&Value::Str(Cow::Borrowed("nop")))
        ); // ws pad
        assert_eq!(
            fl.get("opt.4.kind"),
            Some(&Value::Str(Cow::Borrowed("sackok")))
        );
        assert_eq!(
            fl.get("opt.5.kind"),
            Some(&Value::Str(Cow::Borrowed("nop")))
        ); // pad
        assert_eq!(
            fl.get("opt.6.kind"),
            Some(&Value::Str(Cow::Borrowed("nop")))
        ); // pad
        assert_eq!(
            fl.get("opt.7.sack"),
            Some(&Value::Str(Cow::Borrowed("1,2")))
        );
        assert_eq!(fl.get("opt.8.ts_val"), Some(&Value::Int(0x11223344)));
        assert_eq!(fl.get("opt.8.ts_ecr"), Some(&Value::Int(7)));
        // raw is the wire truth everywhere a len byte exists
        match fl.get("opt.0.raw") {
            Some(Value::Bytes(b)) => assert_eq!(&b[..], &[0x05, 0xb4]),
            other => panic!("raw: {other:?}"),
        }
        // parse-time spans: absolute offsets (bare layer, region at 20)
        let sp = &p.layers[0].field_spans;
        assert_eq!(
            sp.get("opt.0.kind"),
            Some(&FieldSpan::Bytes(20..21)),
            "{sp:?}"
        );
        assert_eq!(sp.get("opt.0.len"), Some(&FieldSpan::Bytes(21..22)));
        assert_eq!(sp.get("opt.0.mss"), Some(&FieldSpan::Bytes(22..24)));
        // sack record: region offset 13 (mss 4 + nop 1 + ws 3 + pad 1 +
        // sackok 2 + pad 1 + pad 1) → value bytes at 35..43
        assert_eq!(sp.get("opt.7.sack"), Some(&FieldSpan::Bytes(35..43)));
        assert_eq!(sp.get("options"), Some(&FieldSpan::None), "{sp:?}");
    }

    /// Unknown kinds craft and dissect through `raw` (the tshark
    /// numeric rendering); tfo/mptcp ride the same path.
    #[test]
    fn record_unknown_kind_raw_roundtrip() {
        let spec = tcp_spec(&[
            ("opt.0.kind", "34"), // tfo
            ("opt.0.raw", "hex:0102030405"),
        ]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
        assert_eq!(&enc.bytes[20..28], &[34, 7, 1, 2, 3, 4, 5, 0][..]);
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "tcp");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        let fl = &p.layers[0].fields;
        assert_eq!(
            fl.get("opt.0.kind"),
            Some(&Value::Str(Cow::Borrowed("tfo")))
        );
        assert_eq!(fl.get("opt.0.len"), Some(&Value::Int(7)));
        match fl.get("opt.0.raw") {
            Some(Value::Bytes(b)) => assert_eq!(&b[..], &[1, 2, 3, 4, 5]),
            other => panic!("raw: {other:?}"),
        }
        // a number outside the vocabulary renders bare (kind 14)
        let spec = tcp_spec(&[("opt.0.kind", "14"), ("opt.0.raw", "hex:aabb")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "tcp");
        assert_eq!(
            p.layers[0].fields.get("opt.0.kind"),
            Some(&Value::Str(Cow::Borrowed("14")))
        );
    }

    /// Records and the list grammar are mutually exclusive (the dhcp
    /// msg_type precedent); a record without a kind is a pointed gap;
    /// an unknown kind name is pointed too.
    #[test]
    fn record_usage_errors() {
        let both = tcp_spec(&[
            ("options", "nop"),
            ("opt.0.kind", "mss"),
            ("opt.0.mss", "1460"),
        ]);
        let err = encode(&registry(), &PacketSpec::new(vec![both], None), &lo_opts()).unwrap_err();
        assert!(
            matches!(err, EncodeError::IncompatibleStack { ref detail } if detail.contains("mutually exclusive")),
            "{err:?}"
        );
        let no_kind = tcp_spec(&[("opt.0.mss", "536")]);
        let err = encode(
            &registry(),
            &PacketSpec::new(vec![no_kind], None),
            &lo_opts(),
        )
        .unwrap_err();
        assert!(
            matches!(err, EncodeError::Unfillable { ref field } if field == "tcp.opt.0.kind"),
            "{err:?}"
        );
        let bad_kind = tcp_spec(&[("opt.0.kind", "bogus")]);
        let err = encode(
            &registry(),
            &PacketSpec::new(vec![bad_kind], None),
            &lo_opts(),
        )
        .unwrap_err();
        assert!(
            matches!(err, EncodeError::IncompatibleStack { ref detail } if detail.contains("unknown option kind")),
            "{err:?}"
        );
        // sack needs at least one value
        let empty_sack = tcp_spec(&[("opt.0.kind", "sack"), ("opt.0.sack", "")]);
        assert!(
            encode(
                &registry(),
                &PacketSpec::new(vec![empty_sack], None),
                &lo_opts()
            )
            .is_err()
        );
    }

    /// Explicit `len` wins verbatim (the craft rule — deliberate
    /// invalidity is a feature); eol/nop carry no length byte home.
    #[test]
    fn record_explicit_len_wins() {
        let spec = tcp_spec(&[
            ("opt.0.kind", "mss"),
            ("opt.0.mss", "1460"),
            ("opt.0.len", "9"),
        ]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
        assert_eq!(enc.bytes[21], 9); // verbatim, unvalidated
        let spec = tcp_spec(&[("opt.0.kind", "eol"), ("opt.0.len", "3")]);
        let err = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap_err();
        assert!(
            matches!(err, EncodeError::IncompatibleStack { ref detail } if detail.contains("no length byte")),
            "{err:?}"
        );
    }

    /// EOL ends the read walk (the trailing grid padding stays in the
    /// `options` region); malformed options stop with never-fatal
    /// anomalies and the region stays raw.
    #[test]
    fn record_read_walk_edges() {
        // eol + padding: one record, nothing after
        let spec = tcp_spec(&[("opt.0.kind", "eol")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
        // eol(1) padded to 4 → 3 zero bytes in the region
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "tcp");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(
            p.layers[0].fields.get("opt.0.kind"),
            Some(&Value::Str(Cow::Borrowed("eol")))
        );
        assert!(!p.layers[0].fields.contains_key("opt.0.len")); // no len byte
        assert!(!p.layers[0].fields.contains_key("opt.1.kind")); // walk ended
        // overrun: mss claiming more than the region holds
        let spec = tcp_spec(&[("options", "hex:0299000000")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "tcp");
        assert!(
            p.anomalies.iter().any(|a| a.path == "tcp.opt.0"),
            "{:?}",
            p.anomalies
        );
        // length below 2
        let spec = tcp_spec(&[("options", "hex:0301")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "tcp");
        assert!(
            p.anomalies
                .iter()
                .any(|a| a.path == "tcp.opt.0" && a.message.contains("below 2")),
            "{:?}",
            p.anomalies
        );
        // malformed shapes degrade silently to raw (the dhcp rule): a
        // 3-byte mss keeps kind/len/raw, no typed mss
        let spec = tcp_spec(&[("options", "hex:020301")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "tcp");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        let fl = &p.layers[0].fields;
        assert_eq!(
            fl.get("opt.0.kind"),
            Some(&Value::Str(Cow::Borrowed("mss")))
        );
        assert!(fl.get("opt.0.mss").is_none());
        assert!(matches!(fl.get("opt.0.raw"), Some(Value::Bytes(_))));
        // guard edges (each typed kind fires ONLY on its own wire shape):
        // a 2-byte option (unknown kind, no data) walks clean; ws with a
        // 4-byte body, sack with a 5-byte body, ts with an 8-byte body —
        // kind/len/raw only, no typed fields.
        for (hex, typed) in [
            ("hex:1902", "opt.0.ws"),               // 2-byte option: walks clean
            ("hex:0304aabb", "opt.0.ws"),           // ws with a 4-byte body
            ("hex:0507aabbccddee", "opt.0.sack"),   // sack with a 5-byte body
            ("hex:0808aabbccddee", "opt.0.ts_val"), // ts with an 8-byte body
        ] {
            let hex = hex.replace(' ', "");
            let spec = tcp_spec(&[("options", hex.as_str())]);
            let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
            let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "tcp");
            assert!(p.anomalies.is_empty(), "{hex}: {:?}", p.anomalies);
            assert!(
                !p.layers[0].fields.contains_key(typed),
                "{hex}: {typed} must stay absent (the guard did not fire)"
            );
        }
        // the full-span table (kill-strength: every span the walk
        // emits, at exact absolute offsets — bare layer, region at 20).
        // mss(4) + sack(10) + ts(10) + ws(4) = 28 → the 4-byte grid
        // exactly (ws carries its own nop pad — the 5th record).
        let spec = tcp_spec(&[
            ("opt.0.kind", "mss"),
            ("opt.0.mss", "1460"),
            ("opt.1.kind", "sack"),
            ("opt.1.sack", "1,2"),
            ("opt.2.kind", "ts"),
            ("opt.2.ts_val", "1"),
            ("opt.2.ts_ecr", "2"),
            ("opt.3.kind", "ws"),
            ("opt.3.ws", "7"),
        ]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "tcp");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        let sp = &p.layers[0].field_spans;
        for (key, want) in [
            ("opt.0.kind", FieldSpan::Bytes(20..21)),
            ("opt.0.len", FieldSpan::Bytes(21..22)),
            ("opt.0.mss", FieldSpan::Bytes(22..24)),
            ("opt.0.raw", FieldSpan::Bytes(22..24)),
            ("opt.1.kind", FieldSpan::Bytes(24..25)),
            ("opt.1.len", FieldSpan::Bytes(25..26)),
            ("opt.1.sack", FieldSpan::Bytes(26..34)),
            ("opt.1.raw", FieldSpan::Bytes(26..34)),
            ("opt.2.kind", FieldSpan::Bytes(34..35)),
            ("opt.2.len", FieldSpan::Bytes(35..36)),
            ("opt.2.ts_val", FieldSpan::Bytes(36..40)),
            ("opt.2.ts_ecr", FieldSpan::Bytes(40..44)),
            ("opt.2.raw", FieldSpan::Bytes(36..44)),
            ("opt.3.kind", FieldSpan::Bytes(44..45)),
            ("opt.3.len", FieldSpan::Bytes(45..46)),
            ("opt.3.ws", FieldSpan::Bytes(46..47)),
            ("opt.3.raw", FieldSpan::Bytes(46..47)),
            ("opt.4.kind", FieldSpan::Bytes(47..48)), // the ws nop pad
        ] {
            assert_eq!(sp.get(key), Some(&want), "{key}: {sp:?}");
        }
        // no sixth record: the walk consumed the region exactly — and
        // the layer span pin (a mutated `offset + hlen` desyncs every
        // record offset).
        assert!(!p.layers[0].fields.contains_key("opt.5.kind"));
        assert_eq!(p.layers[0].span, 0..48);
    }

    /// The craft-side walk edges the read tests cannot reach: the raw
    /// cap (253 ok / 254 the pointed error), sackok carrying an
    /// explicit len (the one 2-byte record), eol/nop wire pins (a
    /// deleted match arm falls into the unknown-kind shape).
    #[test]
    fn record_craft_edge_pins() {
        // 253 bytes of data: the cap holds (the option is 255 bytes).
        let mut big = String::with_capacity(253 * 2);
        big.push_str("hex:");
        for _ in 0..253 {
            big.push_str("aa");
        }
        let spec = tcp_spec(&[("opt.0.kind", "tfo"), ("opt.0.raw", &big)]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec.clone()], None),
            &lo_opts(),
        )
        .expect("253 fits");
        assert_eq!(enc.bytes.len(), 20 + 256); // 255 + one pad byte
        // 254: the pointed error.
        let mut bigger = String::with_capacity(254 * 2);
        bigger.push_str("hex:");
        for _ in 0..254 {
            bigger.push_str("aa");
        }
        let spec = tcp_spec(&[("opt.0.kind", "tfo"), ("opt.0.raw", &bigger)]);
        assert!(encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).is_err());
        // the 2-byte record (unknown kind, empty raw) carries an
        // explicit len — the `<` boundary in the explicit-len check.
        let spec = tcp_spec(&[("opt.0.kind", "34"), ("opt.0.len", "3")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
        assert_eq!(&enc.bytes[20..22], &[34, 3][..]); // verbatim, unvalidated
        // eol/nop wire pins: kind byte ONLY (a deleted arm leaks a len).
        let spec = tcp_spec(&[("opt.0.kind", "eol")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
        assert_eq!(&enc.bytes[20..24], &[0, 0, 0, 0][..]);
        let spec = tcp_spec(&[("opt.0.kind", "nop")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &lo_opts()).unwrap();
        assert_eq!(&enc.bytes[20..24], &[1, 0, 0, 0][..]);
    }
}
