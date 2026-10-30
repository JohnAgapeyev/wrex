#![forbid(unsafe_code)]
//! wrex IPv4 codec (ver/ihl/tos/total_len/id/flags/frag_off/ttl/proto/
//! checksum/src/dst/options; rank 20, parent eth; also a valid stack start).

mod options;

use bytes::{BufMut, Bytes};
use std::borrow::Cow;
use std::net::Ipv4Addr;

use wrex_core::dissect::{FieldSpan, LayerView, NetFacts};
use wrex_core::encode::{EncodeCtx, Patch, flagset_or_default, int_or_default, ipv4_or_default};
use wrex_core::error::DecodeError;
use wrex_core::schema::{
    ChecksumEnd, ChecksumStart, Derived, FieldKind, FieldSchema, LayerSchema, Layout, LengthBase,
    LengthUnits, PseudoSource, RecordSchema,
};
use wrex_core::spec::LayerSpec;
use wrex_core::str_eq;
use wrex_core::value::Value;
use wrex_core::{Anomaly, Codec, DecodeCtx, EncodeError, Next, ReadOutcome};

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
    d("ver", FieldKind::U8, "version (autofill: 4)", Value::Int(4)),
    d(
        "ihl",
        FieldKind::U8,
        "header length in 32-bit words (autofill: derived)",
        Value::Int(0),
    ),
    d("tos", FieldKind::U8, "type of service", Value::Int(0)),
    d(
        "total_len",
        FieldKind::U16,
        "total length (autofill: computed)",
        Value::Int(0),
    ),
    d(
        "id",
        FieldKind::U16,
        "identification (autofill: 0, deterministic)",
        Value::Int(0),
    ),
    FieldSchema {
        name: "flags",
        kind: FieldKind::FlagSet,
        // RFC 791 §3.1, the 3-bit control field MSB-first on the wire:
        //   word bit 15 (0x8000) = reserved ("Bit 0: reserved, must be
        //   zero"), bit 14 (0x4000) = DF, bit 13 (0x2000) = MF.
        // Linux <netinet/ip.h> agrees (IP_RF 0x8000, IP_DF 0x4000,
        // IP_MF 0x2000). The T18a repair landed this table as
        // [mf,df,res] — mf on the reserved bit — and the corpus
        // self-confirmed; the HP3-a/G1 sweep (flags randomizing into
        // the etherparse differential) caught the inversion.
        bit_names: &["res", "df", "mf"],
        default: Value::Int(0),
        required: false,
        doc: "flags aggregate [res,df,mf] (RFC 791: res=bit 15, df=bit 14, mf=bit 13); per-bit subpaths flags.res / flags.df / flags.mf",
    },
    d("frag_off", FieldKind::U16, "fragment offset", Value::Int(0)),
    d(
        "ttl",
        FieldKind::U8,
        "time to live (autofill: 64)",
        Value::Int(64),
    ),
    d(
        "proto",
        FieldKind::U8,
        "protocol (autofill: derived from next layer)",
        Value::Int(0),
    ),
    d(
        "checksum",
        FieldKind::U16,
        "header checksum (autofill: computed)",
        Value::Int(0),
    ),
    d(
        "src",
        FieldKind::Ipv4,
        "source address (autofill: 127.0.0.1; interface primary on send)",
        Value::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
    ),
    d(
        "dst",
        FieldKind::Ipv4,
        "destination address (autofill: 127.0.0.1)",
        Value::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
    ),
    FieldSchema {
        name: "options",
        kind: FieldKind::Bytes,
        bit_names: &[],
        default: Value::Bytes(Bytes::new()),
        required: false,
        doc: "options: eol,nop,rr:IP…,ssrr:IP…,lsrr:IP…,ts:FLAG,CNT, or hex:… (mutually exclusive with the opt.N.* record paths)",
    },
];

/// Tranche 22b: the settable `opt` record section — one record per
/// wire option (the dns `an.0.*` / tcp `opt.0.*` precedent).
static OPT_FIELDS: [FieldSchema; 7] = [
    d(
        "kind",
        FieldKind::Str,
        "option kind: eol|nop|rr|ssrr|lsrr|ts or a bare number (required per record)",
        Value::Str(Cow::Borrowed("")),
    ),
    d(
        "len",
        FieldKind::U8,
        "option length in bytes incl. kind+len (autofill: derived from the value; explicit kept verbatim — eol/nop carry no length byte)",
        Value::Int(0),
    ),
    d(
        "ptr",
        FieldKind::U8,
        "pointer byte (route options: 4; ts: 5 — explicit wins)",
        Value::Int(0),
    ),
    d(
        "route",
        FieldKind::Str,
        "route addresses as IP,IP,… (kind rr/ssrr/lsrr — at least one)",
        Value::Str(Cow::Borrowed("")),
    ),
    d(
        "ts_flag",
        FieldKind::U8,
        "timestamp flags byte (kind ts, RFC 791 §3.2)",
        Value::Int(0),
    ),
    d(
        "ts",
        FieldKind::Str,
        "timestamps as 0xHHHHHHHH,… 4-byte words (kind ts)",
        Value::Str(Cow::Borrowed("")),
    ),
    d(
        "raw",
        FieldKind::Bytes,
        "raw option data after kind+len (unknown kinds — the wire truth)",
        Value::Bytes(Bytes::new()),
    ),
];

static RECORDS: [RecordSchema; 1] = [RecordSchema {
    name: "opt",
    fields: &OPT_FIELDS,
    settable: true,
    max: None,
    doc: "IPv4 options (RFC 791 §3): one record per option, crafted through index paths opt.0.*, … (the dns an.0.* precedent). Route options carry ptr + route address list; ts carries ptr + ts_flag + 4-byte timestamp words; raw covers unknown kinds; len autofills from the value (explicit kept verbatim). Dissect-side the wire truth; eol ends the walk, padding after it stays in the options region.",
}];

/// The kind string this codec implements (ADR 3): children (icmp,
/// udp, tcp) reference `wrex_proto_ip::KIND` in their `parents`
/// instead of hand-written strings, so the registry vocabulary is
/// compile-checked.
pub const KIND: &str = "ipv4";

pub static SCHEMA: LayerSchema = LayerSchema {
    kind: KIND,
    rank: 20,
    parents: &[wrex_proto_eth::KIND, wrex_proto_vlan::KIND],
    doc: "IPv4 (RFC 791). Also a valid stack start. ver=4, ihl derived from options length (explicit ihl wins; invalid values are kept and flagged only under --strict), total_len and checksum autofilled from the packet (explicit values win). proto drives the chain: 1=icmp, 6=tcp, 17=udp, else synthesized `unknown`. Stacks on eth or vlan (802.1Q tag). options grammar: eol,nop,rr:IP,ssrr:IP,lsrr:IP,ts:FLAG,CNT, or hex:BYTES — or the settable opt.N.* record paths (tranche 22b: --ipv4-opt-0-kind rr --ipv4-opt-0-route 10.0.0.1, one record per option, the dns an.0.* precedent; mutually exclusive with the grammar). Dissect renders DSCP/ECN names beside tos (tos.dscp: cs0..cs7/ef/af classes, tos.ecn: not-ect/ect0/ect1/ce). CLI alias: `ip` (--ip-ttl == --ipv4-ttl).",
    fields: &FIELDS,
    records: &RECORDS,
};

/// IPv4 codec unit. Register via [`register`] (the ADR-3 closure);
/// bespoke registries may use `&wrex_proto_ip::CODEC` directly.
pub struct IpCodec;

pub static CODEC: IpCodec = IpCodec;

/// ADR 3 registration closure: register self (dedup-guarded via
/// [`Registry::get`]), then the parent crates'. Self-first keeps
/// `standard()`'s fixed registration order byte-identical —
/// presence, not order, is the guarantee.
pub fn register(r: &mut wrex_core::Registry) {
    if r.get(KIND).is_none() {
        r.register(&CODEC);
    }
    wrex_proto_eth::register(r);
    wrex_proto_vlan::register(r);
}

/// DSCP codepoint names (RFC 2474 §4.2.2 cs0..cs7, RFC 2597 af
/// classes, RFC 3246 ef): rendered beside the raw `tos` byte; other
/// values render bare (the numeric spelling, the tcp `opt.N.kind`
/// rule).
fn render_dscp(code: u8) -> Cow<'static, str> {
    match code {
        0 => Cow::Borrowed("cs0"),
        8 => Cow::Borrowed("cs1"),
        10 => Cow::Borrowed("af11"),
        12 => Cow::Borrowed("af12"),
        14 => Cow::Borrowed("af13"),
        16 => Cow::Borrowed("cs2"),
        18 => Cow::Borrowed("af21"),
        20 => Cow::Borrowed("af22"),
        22 => Cow::Borrowed("af23"),
        24 => Cow::Borrowed("cs3"),
        26 => Cow::Borrowed("af31"),
        28 => Cow::Borrowed("af32"),
        30 => Cow::Borrowed("af33"),
        32 => Cow::Borrowed("cs4"),
        34 => Cow::Borrowed("af41"),
        36 => Cow::Borrowed("af42"),
        38 => Cow::Borrowed("af43"),
        40 => Cow::Borrowed("cs5"),
        46 => Cow::Borrowed("ef"),
        48 => Cow::Borrowed("cs6"),
        56 => Cow::Borrowed("cs7"),
        other => Cow::Owned(other.to_string()),
    }
}

/// ECN codepoint names (RFC 3168 §5): the 2-bit field beside the DSCP.
fn render_ecn(code: u8) -> Cow<'static, str> {
    match code {
        0 => Cow::Borrowed("not-ect"),
        1 => Cow::Borrowed("ect0"),
        2 => Cow::Borrowed("ect1"),
        3 => Cow::Borrowed("ce"),
        other => Cow::Owned(other.to_string()),
    }
}

/// next layer kind → protocol number.
const fn kind_to_proto(kind: Option<&'static str>) -> u8 {
    // (const: str patterns are not const-callable — str_eq chain.)
    match kind {
        Some(k) => {
            if str_eq(k, "icmp") {
                1
            } else if str_eq(k, "tcp") {
                6
            } else if str_eq(k, "udp") {
                17
            } else {
                0
            }
        }
        None => 0,
    }
}

/// protocol number → next layer kind.
const fn proto_to_kind(p: u8) -> &'static str {
    match p {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        _ => "unknown",
    }
}

/// Tranche 22b: ONE `opt.N.*` record → wire bytes (the dns
/// `crafted_records` pattern — kind required, typed values default,
/// explicit len/ptr win verbatim).
fn opt_record_bytes(spec: &LayerSpec, n: usize) -> Result<Vec<u8>, EncodeError> {
    let bad = |detail: String| EncodeError::IncompatibleStack { detail };
    let int = |name: &str, default: u128| -> u128 {
        let key = format!("opt.{n}.{name}");
        match spec.fields.get(key.as_str()) {
            Some(Value::Int(v)) => *v,
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
            field: format!("ipv4.opt.{n}.kind"),
        });
    };
    let code = options::parse_kind(kind)
        .ok_or_else(|| bad(format!("ipv4.opt.{n}.kind: unknown option kind `{kind}`")))?;
    // The route/ts payloads share the explicit-ptr rule (default 4/5).
    let ptr = int("ptr", 0);
    let explicit_ptr = ptr != 0;
    let mut out = match code {
        0 => vec![options::OPT_EOL],
        1 => vec![options::OPT_NOP],
        7 | 131 | 137 => {
            let raw = str_of("route").unwrap_or_default();
            if raw.trim().is_empty() {
                return Err(bad(format!(
                    "ipv4.opt.{n}.route needs at least one address"
                )));
            }
            let ips: Vec<Ipv4Addr> = raw
                .split(',')
                .map(|s| s.trim().parse::<Ipv4Addr>())
                .collect::<Result<_, _>>()
                .map_err(|_| bad(format!("ipv4.opt.{n}.route: bad address in `{raw}`")))?;
            let mut out = vec![
                code,
                (3 + 4 * ips.len()) as u8,
                ptr_or(explicit_ptr, ptr, 4),
            ];
            for ip in &ips {
                out.extend_from_slice(&ip.octets());
            }
            out
        }
        68 => {
            let flag = int("ts_flag", 0) as u8;
            let raw = str_of("ts").unwrap_or_default();
            let mut stamps = Vec::new();
            if !raw.trim().is_empty() {
                for word in raw.split(',') {
                    let w = word.trim();
                    let v = if let Some(h) = w.strip_prefix("0x") {
                        u32::from_str_radix(h, 16)
                    } else {
                        w.parse::<u32>()
                    }
                    .map_err(|_| bad(format!("ipv4.opt.{n}.ts: bad timestamp `{w}`")))?;
                    stamps.extend_from_slice(&v.to_be_bytes());
                }
            }
            let mut out = vec![
                options::OPT_TS,
                (4 + stamps.len()) as u8,
                ptr_or(explicit_ptr, ptr, 5),
                flag,
            ];
            out.extend_from_slice(&stamps);
            out
        }
        // Unknown kinds: `raw` is the data (the wire truth).
        _ => {
            let data = bytes_of("raw").unwrap_or_default();
            if data.len() > 253 {
                return Err(bad(format!(
                    "ipv4.opt.{n}.raw: {} bytes exceeds the 253-byte option data maximum",
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
    // Explicit len wins verbatim (the craft rule).
    let len_key = format!("opt.{n}.len");
    if let Some(Value::Int(v)) = spec.fields.get(len_key.as_str()) {
        if out.len() < 2 {
            return Err(bad(format!(
                "ipv4.opt.{n}.len: `{}` carries no length byte",
                options::render_kind(code)
            )));
        }
        out[1] = *v as u8;
    }
    Ok(out)
}

/// Explicit ptr wins; 0 (unset) falls back to the kind default.
fn ptr_or(explicit: bool, v: u128, default: u8) -> u8 {
    if explicit { v as u8 } else { default }
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
            detail: "ipv4.options and opt.N.* records are mutually exclusive".to_string(),
        });
    }
    let mut raw = if records.is_empty() { raw } else { records };
    raw.extend(std::iter::repeat_n(0u8, options::pad_len(raw.len())));
    Ok(raw)
}

impl Codec for IpCodec {
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
        // Explicit ihl wins (invalid values kept: deliberate invalid packets
        // are a feature); otherwise derived from the options region.
        let ihl = match spec.fields.get("ihl") {
            Some(Value::Int(v)) => *v as u8 & 0x0f,
            _ => (5 + opts.len() / 4) as u8 & 0x0f,
        };
        let ver = int_or_default(spec, &FIELDS[0], af);
        ctx.buf.put_u8((((ver as u8) & 0x0f) << 4) | ihl);
        ctx.defer(Patch::MinNibble {
            at: start,
            min: 5,
            path: "ipv4.ihl",
        });
        ctx.buf.put_u8(int_or_default(spec, &FIELDS[2], af) as u8); // tos
        let at_total = ctx.buf.len();
        let total_explicit = spec.fields.contains_key("total_len");
        if let Some(Value::Int(v)) = spec.fields.get("total_len") {
            ctx.buf.put_u16(*v as u16);
        } else {
            ctx.buf.put_u16(0); // total_len placeholder
        }
        ctx.buf.put_u16(int_or_default(spec, &FIELDS[4], af) as u16); // id
        let flags = flagset_or_default(spec, &FIELDS[5], af) as u16;
        let frag = int_or_default(spec, &FIELDS[6], af) as u16;
        // flags occupy the top 3 bits (reserved + df + mf): mask explicit
        // values so shifting cannot overflow u16.
        ctx.buf.put_u16(((flags & 0x7) << 13) | (frag & 0x1fff));
        ctx.buf.put_u8(int_or_default(spec, &FIELDS[7], af) as u8); // ttl
        let proto = match spec.fields.get("proto") {
            Some(Value::Int(v)) => *v as u8,
            _ if af => kind_to_proto(ctx.next),
            _ => 0,
        };
        ctx.buf.put_u8(proto);
        let at_ck = ctx.buf.len();
        let ck_explicit = spec.fields.contains_key("checksum");
        if let Some(Value::Int(v)) = spec.fields.get("checksum") {
            ctx.buf.put_u16(*v as u16);
        } else {
            ctx.buf.put_u16(0); // checksum placeholder
        }
        ctx.buf
            .extend_from_slice(&ipv4_or_default(spec, &FIELDS[10], af).octets());
        ctx.buf
            .extend_from_slice(&ipv4_or_default(spec, &FIELDS[11], af).octets());
        ctx.buf.extend_from_slice(&opts);
        let header_end = ctx.buf.len();
        // Backpatches (engine resolves after payload append; explicit values
        // are kept and only re-verified under --strict).
        ctx.defer(Patch::Length {
            at: at_total,
            base: start,
            explicit: total_explicit,
            path: "ipv4.total_len",
        });
        ctx.defer(Patch::Checksum {
            at: at_ck,
            start,
            end: Some(header_end),
            pseudo: None,
            explicit: ck_explicit,
            path: "ipv4.checksum",
        });
        // Record NetFacts before L4 writes (pseudo-header source).
        wrex_core::encode::record_net_facts(
            ctx,
            NetFacts::V4 {
                src: ipv4_or_default(spec, &FIELDS[10], af),
                dst: ipv4_or_default(spec, &FIELDS[11], af),
                proto,
            },
        );
        // Tranche 17a: the upper-layer packet begins right after this
        // header (options included — they are part of the ipv4 header).
        // The L4 checksum defers read it from the threaded facts; with
        // no extension chain it equals the L4 layer's own start, so
        // every pre-17a wire byte stays identical.
        ctx.facts.upper_start = Some(header_end);
        Ok(())
    }

    fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
        if bytes.is_empty() {
            return ReadOutcome::Empty;
        }
        if bytes.len() < 20 {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: "ipv4",
                    need: 20,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let ver = bytes[0] >> 4;
        let ihl = bytes[0] & 0x0f;
        if ihl < 5 {
            ctx.anomalies.push(Anomaly::new("ipv4.ihl", "below 5"));
            return ReadOutcome::Anomaly(
                DecodeError::BadField {
                    path: "ipv4.ihl".into(),
                    reason: format!("ihl {ihl} below 5"),
                },
                Next::Payload,
            );
        }
        let hlen = ihl as usize * 4;
        if bytes.len() < hlen {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: "ipv4",
                    need: hlen,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let tos = bytes[1];
        let total_len = u16::from_be_bytes([bytes[2], bytes[3]]);
        let id = u16::from_be_bytes([bytes[4], bytes[5]]);
        let flags_frag = u16::from_be_bytes([bytes[6], bytes[7]]);
        let ttl = bytes[8];
        let proto = bytes[9];
        let found_ck = u16::from_be_bytes([bytes[10], bytes[11]]);
        let src = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
        let dst = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);

        // Checksum verify (non-fatal anomaly on mismatch).
        let mut acc = wrex_core::ChecksumAccumulator::new();
        acc.add_bytes(&bytes[..10]);
        acc.add_u16(0);
        acc.add_bytes(&bytes[12..hlen]);
        let computed = acc.value();
        if found_ck != computed {
            ctx.anomalies.push(Anomaly::new(
                "ipv4.checksum",
                format!("mismatch (computed 0x{computed:04x}, found 0x{found_ck:04x})"),
            ));
        }
        // Length-vs-actual (non-fatal).
        if total_len != 0 && total_len as usize != bytes.len() {
            ctx.anomalies.push(Anomaly::new(
                "ipv4.total_len",
                format!(
                    "mismatch (expected {total_len} (0x{total_len:04x}), found {} bytes)",
                    bytes.len()
                ),
            ));
        }

        // Flag names for the 3-bit field (RFC 791: res=13, df=14, mf=15).
        // Names render df-then-mf (the tshark order).
        let agg = (flags_frag >> 13) & 0x7;
        // Render in `bit_names` MSB-first order ([res,df,mf] — RFC 791
        // wire order), and render ALL named bits: the reserved bit is
        // a real wire bit (the HP3-a sweep caught the pre-fix renderer
        // emitting a stale order and silently dropping `res`).
        let mut names: Vec<Value> = Vec::new();
        if agg & 0b100 != 0 {
            names.push(Value::Str(Cow::Borrowed("res")));
        }
        if agg & 0b010 != 0 {
            names.push(Value::Str(Cow::Borrowed("df")));
        }
        if agg & 0b001 != 0 {
            names.push(Value::Str(Cow::Borrowed("mf")));
        }

        let mut fields = std::collections::BTreeMap::new();
        fields.insert("ver".into(), Value::Int(ver as u128));
        fields.insert("ihl".into(), Value::Int(ihl as u128));
        fields.insert("tos".into(), Value::Int(tos as u128));
        fields.insert("total_len".into(), Value::Int(total_len as u128));
        fields.insert("id".into(), Value::Int(id as u128));
        fields.insert("flags".into(), Value::List(names));
        fields.insert("frag_off".into(), Value::Int((flags_frag & 0x1fff) as u128));
        fields.insert("ttl".into(), Value::Int(ttl as u128));
        fields.insert("proto".into(), Value::Int(proto as u128));
        fields.insert("checksum".into(), Value::Int(found_ck as u128));
        fields.insert("src".into(), Value::Ipv4(src));
        fields.insert("dst".into(), Value::Ipv4(dst));
        fields.insert(
            "options".into(),
            Value::Bytes(Bytes::copy_from_slice(&bytes[20..hlen])),
        );

        // Tranche 22b: parse-time spans — the dissect-only DSCP/ECN name
        // subpaths over the tos byte (the dns `flags.z` precedent: extra
        // fields-map keys, geometry codec-side), and the typed `opt.N.*`
        // record walk over the options region (the dhcp pattern).
        let mut spans: std::collections::BTreeMap<Cow<'static, str>, FieldSpan> =
            std::collections::BTreeMap::new();
        let tos_at = ctx.offset + 1;
        spans.insert(
            "tos.dscp".into(),
            FieldSpan::Bits {
                container: tos_at..tos_at + 1,
                shift: 0,
                width: 6,
            },
        );
        spans.insert(
            "tos.ecn".into(),
            FieldSpan::Bits {
                container: tos_at..tos_at + 1,
                shift: 6,
                width: 2,
            },
        );
        fields.insert("tos.dscp".into(), Value::Str(render_dscp(tos >> 2)));
        fields.insert("tos.ecn".into(), Value::Str(render_ecn(tos & 0x3)));

        // The option walk (eol ends it; a malformed option stops with a
        // never-fatal anomaly, the rest stays raw in `options`). The
        // walk consumes a shrinking slice (no running cursor: a
        // mutated advance cannot hang — the kill-strength rule).
        let region = &bytes[20..hlen];
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
                    format!("ipv4.opt.{i}"),
                    "option header overruns the region",
                ));
                break;
            };
            let olen = len_b as usize;
            if olen < 2 {
                ctx.anomalies.push(Anomaly::new(
                    format!("ipv4.opt.{i}"),
                    format!("option length {olen} below 2"),
                ));
                break;
            }
            if olen > rest.len() {
                ctx.anomalies.push(Anomaly::new(
                    format!("ipv4.opt.{i}"),
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
            // dhcp rule: the guard does not fire, `raw` covers).
            match kind {
                7 | 131 | 137 if data.len() >= 5 => {
                    spans.insert(
                        format!("opt.{i}.ptr").into(),
                        FieldSpan::Bytes(dat..dat + 1),
                    );
                    fields.insert(format!("opt.{i}.ptr").into(), Value::Int(data[0] as u128));
                    let addrs = &data[1..];
                    if addrs.len().is_multiple_of(4) && !addrs.is_empty() {
                        let route = addrs
                            .as_chunks::<4>()
                            .0
                            .iter()
                            .map(|c| Ipv4Addr::from(*c).to_string())
                            .collect::<Vec<_>>()
                            .join(",");
                        spans.insert(
                            format!("opt.{i}.route").into(),
                            FieldSpan::Bytes(dat + 1..dat + 1 + addrs.len()),
                        );
                        fields.insert(format!("opt.{i}.route").into(), Value::Str(route.into()));
                    }
                }
                68 if data.len() >= 2 => {
                    spans.insert(
                        format!("opt.{i}.ptr").into(),
                        FieldSpan::Bytes(dat..dat + 1),
                    );
                    spans.insert(
                        format!("opt.{i}.ts_flag").into(),
                        FieldSpan::Bytes(dat + 1..dat + 2),
                    );
                    fields.insert(format!("opt.{i}.ptr").into(), Value::Int(data[0] as u128));
                    fields.insert(
                        format!("opt.{i}.ts_flag").into(),
                        Value::Int(data[1] as u128),
                    );
                    let stamps = &data[2..];
                    if stamps.len().is_multiple_of(4) && !stamps.is_empty() {
                        let ts = stamps
                            .as_chunks::<4>()
                            .0
                            .iter()
                            .map(|c| format!("0x{:08x}", u32::from_be_bytes(*c)))
                            .collect::<Vec<_>>()
                            .join(",");
                        spans.insert(
                            format!("opt.{i}.ts").into(),
                            FieldSpan::Bytes(dat + 2..dat + 2 + stamps.len()),
                        );
                        fields.insert(format!("opt.{i}.ts").into(), Value::Str(ts.into()));
                    }
                }
                _ => {}
            }
            i += 1;
            rest = &rest[olen..];
        }

        ctx.facts.net = Some(NetFacts::V4 { src, dst, proto });
        // Tranche 17a: the upper-layer packet begins after the full
        // header (options included — `hlen` is ihl*4).
        ctx.facts.upper_start = Some(ctx.offset + hlen);
        // A fragment carrier (mf set or a nonzero offset — RFC 791
        // §2.3/§3.1): the L4 checksum was folded over the ORIGINAL
        // unfragmented packet and can never verify from a single
        // fragment. The L4 verifies skip (the HP3-b foreign-fragment
        // corpus drove the fix; reassembled output verifies instead).
        ctx.facts.fragmented = agg & 0b001 != 0 || (flags_frag & 0x1fff) != 0;
        let view = LayerView {
            kind: "ipv4",
            span: ctx.offset..ctx.offset + hlen,
            field_spans: spans,
            fields,
        };
        ReadOutcome::Layer(view, Some(Next::Kind(proto_to_kind(proto))))
    }

    /// Tranche 11b fixed layouts (base 20 bytes; ver/ihl and
    /// flags/frag_off are bit windows; `options` is dynamic → None).
    fn layouts(&self) -> &'static [(&'static str, Layout)] {
        &[
            (
                "ver",
                Layout::Bits {
                    at: 0,
                    shift: 0,
                    width: 4,
                },
            ),
            (
                "ihl",
                Layout::Bits {
                    at: 0,
                    shift: 4,
                    width: 4,
                },
            ),
            ("tos", Layout::Bytes { at: 1, len: 1 }),
            ("total_len", Layout::Bytes { at: 2, len: 2 }),
            ("id", Layout::Bytes { at: 4, len: 2 }),
            (
                "flags",
                Layout::Bits {
                    at: 6,
                    shift: 0,
                    width: 3,
                },
            ),
            (
                "frag_off",
                Layout::Bits {
                    at: 6,
                    shift: 3,
                    width: 13,
                },
            ),
            ("ttl", Layout::Bytes { at: 8, len: 1 }),
            ("proto", Layout::Bytes { at: 9, len: 1 }),
            ("checksum", Layout::Bytes { at: 10, len: 2 }),
            ("src", Layout::Bytes { at: 12, len: 4 }),
            ("dst", Layout::Bytes { at: 16, len: 4 }),
        ]
    }

    /// `total_len` = frame end − layer start; `checksum` covers the
    /// header (layer span end, options included), no pseudo-header.
    fn derived(&self) -> &'static [Derived] {
        &[
            Derived::Length {
                field: "total_len",
                at: 2,
                base: LengthBase::LayerStart,
                units: LengthUnits::Bytes,
            },
            Derived::Checksum {
                field: "checksum",
                at: 10,
                start: ChecksumStart::Layer,
                end: ChecksumEnd::Layer,
                pseudo: PseudoSource::None,
            },
        ]
    }
}

#[cfg(feature = "test-util")]
pub mod strategy {
    //! proptest strategies for `LayerSpec` (behind `test-util`).
    use proptest::prelude::*;
    use wrex_core::spec::LayerSpec;
    use wrex_core::value::Value;

    /// Valid ipv4 specs: any header values, options from a small valid set.
    /// Tranche 22b: the `opt` record section samples too — one random
    /// valid record shape (G1: every settable record field randomized;
    /// `len` is the recorded autofill exemption).
    pub fn strategy() -> BoxedStrategy<LayerSpec> {
        let ip = any::<u32>().prop_map(|v| Value::Ipv4(std::net::Ipv4Addr::from(v)));
        let opts = proptest::option::of(proptest::sample::select(vec![
            "eol".to_string(),
            "nop,nop".to_string(),
            "rr:10.0.0.1".to_string(),
            "ssrr:1.2.3.4,5.6.7.8".to_string(),
            "lsrr:1.1.1.1".to_string(),
            "hex:01020304".to_string(),
        ]));
        // One record shape per sample; every record field covered
        // across the pool (kind/ptr/route/ts_flag/ts/raw). The value
        // strategies are arithmetic-free (ranges/selects — the
        // kill-strength rule) and the shape dispatch is a plain match
        // the in-crate audit (below) pins per arm.
        let rec = proptest::option::of((
            (0usize..6),
            any::<u32>(),
            any::<u32>(),
            (4u8..=15),
            any::<u8>(),
            proptest::collection::vec(any::<u8>(), 0..=12),
            proptest::sample::select(vec![
                "9".to_string(),
                "14".to_string(),
                "25".to_string(),
                "77".to_string(),
            ]),
        ))
        .prop_map(|opt| {
            opt.map(|(choice, a, b, ptr, flag, raw, unknown)| {
                let addr = |v: u32| std::net::Ipv4Addr::from(v);
                let mut f = std::collections::BTreeMap::new();
                match choice {
                    0 => {
                        f.insert("kind", Value::Str("rr".into()));
                        f.insert("route", Value::Str(addr(a).to_string().into()));
                        f.insert("ptr", Value::Int(ptr as u128));
                    }
                    1 => {
                        f.insert("kind", Value::Str("ssrr".into()));
                        f.insert(
                            "route",
                            Value::Str(format!("{},{}", addr(a), addr(b)).into()),
                        );
                    }
                    2 => {
                        f.insert("kind", Value::Str("lsrr".into()));
                        f.insert("route", Value::Str(addr(b).to_string().into()));
                    }
                    3 => {
                        f.insert("kind", Value::Str("ts".into()));
                        f.insert("ts_flag", Value::Int(flag as u128));
                        f.insert("ts", Value::Str(format!("0x{a:08x},0x{b:08x}").into()));
                    }
                    4 => {
                        f.insert("kind", Value::Str("nop".into()));
                    }
                    _ => {
                        // Unknown kind (a select spelling), raw data.
                        f.insert("kind", Value::Str(unknown.into()));
                        f.insert("raw", Value::Bytes(bytes::Bytes::from(raw)));
                    }
                }
                f
            })
        });
        (
            any::<u8>(),
            any::<u16>(),
            proptest::sample::select(vec![0u8, 32, 64, 255]),
            // flags is the full 3-bit window [mf,df,res] (G1: never
            // randomized before — the mf bug's blind spot).
            proptest::sample::select(vec![0u8, 0b001, 0b010, 0b100, 0b111]),
            // frag_off is a 13-bit field: valid range only.
            (0u16..0x2000),
            ip.clone(),
            ip,
            opts,
            rec,
        )
            .prop_map(|(tos, id, ttl, flags, frag, src, dst, opts, rec)| {
                let mut fields = std::collections::BTreeMap::new();
                fields.insert("tos".into(), Value::Int(tos as u128));
                fields.insert("id".into(), Value::Int(id as u128));
                fields.insert("flags".into(), Value::Int(flags as u128));
                fields.insert("ttl".into(), Value::Int(ttl as u128));
                fields.insert("frag_off".into(), Value::Int(frag as u128));
                fields.insert("src".into(), src);
                fields.insert("dst".into(), dst);
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
                LayerSpec::with_fields("ipv4", fields)
            })
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
        for kind in ["rr", "ssrr", "lsrr", "ts", "nop"] {
            assert!(
                kinds.contains(&kind.to_string()),
                "kind {kind} never sampled: {kinds:?}"
            );
        }
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
    use wrex_core::dissect::DecodeCtx;
    use wrex_core::encode::{EncodeOpts, encode};
    use wrex_core::spec::PacketSpec;
    use wrex_core::value::parse_value;

    fn ip_spec(fields: &[(&str, &str)]) -> LayerSpec {
        let mut map = BTreeMap::new();
        for (k, v) in fields {
            if *k == "options" {
                // Options use the list grammar, not the Bytes value grammar.
                map.insert(
                    Cow::Owned(k.to_string()),
                    Value::Str((*v).to_string().into()),
                );
                continue;
            }
            // Tranche 22b: `opt.N.*` record paths parse through their
            // record field schemas.
            let value = match SCHEMA.resolve(k) {
                Some(wrex_core::ResolvedField::Field(fs)) => parse_value(fs, v).unwrap(),
                Some(wrex_core::ResolvedField::RecordField { field, .. }) => {
                    parse_value(field, v).unwrap()
                }
                Some(wrex_core::ResolvedField::FlagBit { .. }) => {
                    wrex_core::parse_bool(v).map(Value::Bool).unwrap()
                }
                None => panic!("no field {k}"),
            };
            map.insert(Cow::Owned(k.to_string()), value);
        }
        LayerSpec::with_fields("ipv4", map)
    }

    fn registry() -> Registry {
        let mut r = Registry::empty();
        r.register(&CODEC);
        r
    }

    /// ADR 3: eth is a real parent dep, so this registers the actual
    /// eth codec through the `register()` closure and dissects a
    /// crafted eth→ipv4 frame end to end — the string dispatch table
    /// can no longer drift from the kinds it names (no stand-in).
    #[test]
    fn eth_dispatches_into_ipv4_with_real_codecs() {
        let mut r = wrex_core::Registry::empty();
        register(&mut r);
        let spec = wrex_core::spec::PacketSpec::new(
            vec![
                wrex_core::spec::LayerSpec::new(wrex_proto_eth::KIND),
                ip_spec(&[]),
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
        let p = wrex_core::dissect::dissect(&r, &enc.bytes, wrex_proto_eth::KIND);
        // The trailing `unknown` is honest engine behavior: nothing
        // stacks inside ipv4 in this spec (children are the dispatch
        // direction — not linkable here), so proto autofills to 0 and
        // the synthetic layer carries the (empty) remainder.
        assert_eq!(
            p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
            vec![wrex_proto_eth::KIND, KIND, "unknown"],
            "eth.type 0x0800 must chain into the real ipv4 codec"
        );
    }

    #[test]
    fn golden_header_autofill() {
        let spec = ip_spec(&[("src", "127.0.0.1"), ("dst", "127.0.0.1")]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(enc.bytes.len(), 20);
        assert_eq!(enc.bytes[0], 0x45);
        assert_eq!(enc.bytes[8], 64); // ttl
        // total_len = 20
        assert_eq!(u16::from_be_bytes([enc.bytes[2], enc.bytes[3]]), 20);
        // checksum over header, zeroed ck field:
        let mut acc = wrex_core::ChecksumAccumulator::new();
        acc.add_bytes(&enc.bytes[..10]);
        acc.add_u16(0);
        acc.add_bytes(&enc.bytes[12..]);
        assert_eq!(
            u16::from_be_bytes([enc.bytes[10], enc.bytes[11]]),
            acc.value()
        );
    }

    #[test]
    fn explicit_invalid_overrides_kept_unvalidated() {
        // ihl=4 (invalid) + bogus checksum: kept as-is without --strict
        let spec = ip_spec(&[
            ("ihl", "4"),
            ("checksum", "0xdead"),
            ("total_len", "999"),
            ("src", "1.2.3.4"),
            ("dst", "5.6.7.8"),
        ]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts::default(),
        )
        .unwrap();
        // autofill off: ver nibble 0; explicit ihl=4 kept; user values kept
        assert_eq!(enc.bytes[0], 0x04);
        assert_eq!(u16::from_be_bytes([enc.bytes[2], enc.bytes[3]]), 999);
        assert_eq!(u16::from_be_bytes([enc.bytes[10], enc.bytes[11]]), 0xdead);
        assert!(enc.violations.is_empty());
    }

    #[test]
    fn strict_catches_invalid_overrides() {
        let spec = ip_spec(&[
            ("ihl", "4"),
            ("checksum", "0xdead"),
            ("total_len", "999"),
            ("src", "1.2.3.4"),
            ("dst", "5.6.7.8"),
        ]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts {
                autofill: true,
                strict: true,
                ..Default::default()
            },
        )
        .unwrap();
        let paths: Vec<&str> = enc.violations.iter().map(|v| v.path.as_str()).collect();
        assert!(paths.contains(&"ipv4.total_len"), "{paths:?}");
        assert!(paths.contains(&"ipv4.checksum"), "{paths:?}");
        // ihl explicit: written as nibble; min-nibble check sees ihl=4 < 5
        assert!(paths.contains(&"ipv4.ihl"), "{paths:?}");
    }

    #[test]
    fn options_roundtrip() {
        let spec = ip_spec(&[
            ("src", "10.0.0.1"),
            ("dst", "10.0.0.2"),
            ("options", "nop,rr:1.2.3.4,ssrr:9.9.9.9,10.10.10.10"),
        ]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        // nop(1) + rr(3+16=19?)… total options = 1 + (3+4*1=… rr 1 ip → 7) + ssrr 2 ips (3+8=11) = 19 → pad 1 → 20
        assert_eq!(enc.bytes.len(), 40); // 20 + 20
        assert_eq!(enc.bytes[0], 0x4a); // ihl = 5 + 5
        // dissect back: options hex equals encoded region
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "ipv4");
        assert_eq!(p.layers[0].kind, "ipv4");
        match p.layers[0].fields.get("options") {
            Some(Value::Bytes(b)) => assert_eq!(&b[..], &enc.bytes[20..40]),
            other => panic!("options bytes: {other:?}"),
        }
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        // ihl from re-dissect
        assert_eq!(p.layers[0].fields.get("ihl"), Some(&Value::Int(10)));
    }

    #[test]
    fn read_truncated_and_bad_ihl() {
        let mut ctx = DecodeCtx::new(0);
        assert!(matches!(
            CODEC.read(&[0x45; 10], &mut ctx),
            ReadOutcome::Anomaly(DecodeError::Truncated { kind: "ipv4", .. }, _)
        ));
        let mut ctx = DecodeCtx::new(0);
        let mut bad = vec![0x44u8, 0, 20, 0, 0, 0, 0, 0, 64, 17, 0, 0];
        bad.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        match CODEC.read(&bad, &mut ctx) {
            ReadOutcome::Anomaly(DecodeError::BadField { path, .. }, _) => {
                assert_eq!(path, "ipv4.ihl");
                assert_eq!(ctx.anomalies.len(), 1);
            }
            other => panic!("expected badfield, got {other:?}"),
        }
    }

    #[test]
    fn checksum_mismatch_anomaly_on_read() {
        // valid header, then corrupt checksum byte
        let spec = ip_spec(&[("src", "127.0.0.1"), ("dst", "127.0.0.1")]);
        let mut enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut bytes = enc.bytes.to_vec();
        bytes[10] ^= 0xff;
        let p = wrex_core::dissect::dissect(&registry(), &bytes, "ipv4");
        assert_eq!(p.layers[0].kind, "ipv4"); // still dissects
        assert_eq!(p.anomalies.len(), 1);
        assert!(
            p.anomalies[0].path.contains("checksum"),
            "{:?}",
            p.anomalies[0]
        );
        let _ = &mut enc;
    }

    // --- tranche 22b: settable opt records + DSCP/ECN rendering ---------

    /// One record per kind → wire golden; the route/ts payloads carry
    /// their pointer bytes (ptr defaults 4/5).
    #[test]
    fn record_craft_wire_gold() {
        let spec = ip_spec(&[
            ("opt.0.kind", "nop"),
            ("opt.1.kind", "rr"),
            ("opt.1.route", "10.0.0.1,10.0.0.2"),
            ("opt.2.kind", "ssrr"),
            ("opt.2.route", "9.9.9.9"),
            ("opt.2.ptr", "8"),
            ("opt.3.kind", "ts"),
            ("opt.3.ts_flag", "1"),
            ("opt.3.ts", "0x11223344,0x55667788"),
        ]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        let want: Vec<u8> = [
            &[0x01][..],                                   // nop
            &[0x07, 0x0b, 0x04, 10, 0, 0, 1, 10, 0, 0, 2], // rr 10.0.0.1,10.0.0.2
            &[0x89, 0x07, 0x08, 9, 9, 9, 9],               // ssrr ptr 8
            &[
                0x44, 0x0c, 0x05, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            ], // ts flag 1, 2 stamps
        ]
        .concat();
        // nop(1) + rr(11) + ssrr(7) + ts(12) = 31 → pad 1 → 32
        assert_eq!(enc.bytes.len(), 20 + 32);
        assert_eq!(&enc.bytes[20..20 + 31], &want[..]);
        // dissect back: typed records, no anomalies
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "ipv4");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        let fl = &p.layers[0].fields;
        assert_eq!(
            fl.get("opt.0.kind"),
            Some(&Value::Str(Cow::Borrowed("nop")))
        );
        assert_eq!(fl.get("opt.1.kind"), Some(&Value::Str(Cow::Borrowed("rr"))));
        assert_eq!(fl.get("opt.1.ptr"), Some(&Value::Int(4)));
        assert_eq!(
            fl.get("opt.1.route"),
            Some(&Value::Str(Cow::Borrowed("10.0.0.1,10.0.0.2")))
        );
        assert_eq!(fl.get("opt.2.ptr"), Some(&Value::Int(8))); // explicit wins
        assert_eq!(
            fl.get("opt.2.route"),
            Some(&Value::Str(Cow::Borrowed("9.9.9.9")))
        );
        assert_eq!(fl.get("opt.3.ts_flag"), Some(&Value::Int(1)));
        assert_eq!(fl.get("opt.3.ptr"), Some(&Value::Int(5))); // ts pointer default
        assert_eq!(
            fl.get("opt.3.ts"),
            Some(&Value::Str(Cow::Borrowed("0x11223344,0x55667788")))
        );
        // spans: route addresses at absolute offsets
        let sp = &p.layers[0].field_spans;
        assert_eq!(
            sp.get("opt.1.route"),
            Some(&FieldSpan::Bytes(20 + 1 + 3..20 + 1 + 3 + 8)),
            "{sp:?}"
        );
        assert_eq!(sp.get("options"), Some(&FieldSpan::None), "{sp:?}");
    }

    /// DSCP/ECN names render beside the raw tos byte (the dissect-only
    /// subpaths carry real bit windows — patchable through the spans).
    #[test]
    fn dscp_ecn_rendering() {
        for (tos, dscp, ecn) in [
            (0x00u8, "cs0", "not-ect"),
            (0x20, "cs1", "not-ect"),
            (0x28, "af11", "not-ect"),
            (0xb8, "ef", "not-ect"),
            (0xb9, "ef", "ect0"),
            (0x03, "cs0", "ce"),
            (0x06, "1", "ect1"), // unnamed dscp renders bare
        ] {
            let spec = ip_spec(&[("tos", &tos.to_string())]);
            let enc = encode(
                &registry(),
                &PacketSpec::new(vec![spec], None),
                &EncodeOpts::default(),
            )
            .unwrap();
            let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "ipv4");
            assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
            let fl = &p.layers[0].fields;
            assert_eq!(fl.get("tos"), Some(&Value::Int(tos as u128)));
            assert_eq!(fl.get("tos.dscp"), Some(&Value::Str(Cow::Borrowed(dscp))));
            assert_eq!(fl.get("tos.ecn"), Some(&Value::Str(Cow::Borrowed(ecn))));
            let sp = &p.layers[0].field_spans;
            assert_eq!(
                sp.get("tos.dscp"),
                Some(&FieldSpan::Bits {
                    container: 1..2,
                    shift: 0,
                    width: 6
                }),
                "{sp:?}"
            );
            assert_eq!(
                sp.get("tos.ecn"),
                Some(&FieldSpan::Bits {
                    container: 1..2,
                    shift: 6,
                    width: 2
                }),
                "{sp:?}"
            );
        }
    }

    /// Usage errors: grammar/records mutual exclusion, missing kind,
    /// unknown kind, route-less route option; eol ends the read walk;
    /// malformed options stop with never-fatal anomalies.
    #[test]
    fn record_usage_errors_and_walk_edges() {
        let both = ip_spec(&[
            ("options", "nop"),
            ("opt.0.kind", "rr"),
            ("opt.0.route", "1.2.3.4"),
        ]);
        let err = encode(
            &registry(),
            &PacketSpec::new(vec![both], None),
            &EncodeOpts::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, EncodeError::IncompatibleStack { ref detail } if detail.contains("mutually exclusive")),
            "{err:?}"
        );
        let no_kind = ip_spec(&[("opt.0.route", "1.2.3.4")]);
        let err = encode(
            &registry(),
            &PacketSpec::new(vec![no_kind], None),
            &EncodeOpts::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, EncodeError::Unfillable { ref field } if field == "ipv4.opt.0.kind"),
            "{err:?}"
        );
        let no_route = ip_spec(&[("opt.0.kind", "rr")]);
        let err = encode(
            &registry(),
            &PacketSpec::new(vec![no_route], None),
            &EncodeOpts::default(),
        )
        .unwrap_err();
        assert!(
            matches!(err, EncodeError::IncompatibleStack { ref detail } if detail.contains("at least one address")),
            "{err:?}"
        );
        // eol record: walk ends, grid padding stays raw in `options`
        let spec = ip_spec(&[("opt.0.kind", "eol")]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "ipv4");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(
            p.layers[0].fields.get("opt.0.kind"),
            Some(&Value::Str(Cow::Borrowed("eol")))
        );
        assert!(!p.layers[0].fields.contains_key("opt.1.kind"));
        // unknown kind + raw roundtrip; overrun anomaly stops the walk
        let spec = ip_spec(&[("opt.0.kind", "25"), ("opt.0.raw", "hex:deadbeef")]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "ipv4");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(
            p.layers[0].fields.get("opt.0.kind"),
            Some(&Value::Str(Cow::Borrowed("25")))
        );
        match p.layers[0].fields.get("opt.0.raw") {
            Some(Value::Bytes(b)) => assert_eq!(&b[..], &[0xde, 0xad, 0xbe, 0xef]),
            other => panic!("raw: {other:?}"),
        }
        let spec = ip_spec(&[("options", "hex:07630000")]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts::default(),
        )
        .unwrap();
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "ipv4");
        assert!(
            p.anomalies.iter().any(|a| a.path == "ipv4.opt.0"),
            "{:?}",
            p.anomalies
        );
    }

    /// The read-walk guard edges (each typed kind fires ONLY on its own
    /// wire shape) and the full-span table at exact absolute offsets
    /// — bare layer, region at 20; nop(1) + rr(11) + ts(12) = 24 → the
    /// 4-byte grid exactly, no padding.
    #[test]
    fn record_read_walk_spans_and_guards() {
        let spec = ip_spec(&[
            ("opt.0.kind", "nop"),
            ("opt.1.kind", "rr"),
            ("opt.1.route", "10.0.0.1,10.0.0.2"),
            ("opt.2.kind", "ts"),
            ("opt.2.ts_flag", "1"),
            ("opt.2.ts", "0x11223344,0x55667788"),
        ]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "ipv4");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        let sp = &p.layers[0].field_spans;
        for (key, want) in [
            ("opt.0.kind", FieldSpan::Bytes(20..21)),
            ("opt.1.kind", FieldSpan::Bytes(21..22)),
            ("opt.1.len", FieldSpan::Bytes(22..23)),
            ("opt.1.ptr", FieldSpan::Bytes(23..24)),
            ("opt.1.route", FieldSpan::Bytes(24..32)),
            ("opt.1.raw", FieldSpan::Bytes(23..32)),
            ("opt.2.kind", FieldSpan::Bytes(32..33)),
            ("opt.2.len", FieldSpan::Bytes(33..34)),
            ("opt.2.ptr", FieldSpan::Bytes(34..35)),
            ("opt.2.ts_flag", FieldSpan::Bytes(35..36)),
            ("opt.2.ts", FieldSpan::Bytes(36..44)),
            ("opt.2.raw", FieldSpan::Bytes(34..44)),
        ] {
            assert_eq!(sp.get(key), Some(&want), "{key}: {sp:?}");
        }
        assert!(!p.layers[0].fields.contains_key("opt.3.kind"));
        // the layer span pin (kill-strength: a mutated `offset + hlen`
        // would shorten the span and desync every record offset).
        assert_eq!(p.layers[0].span, 0..44);
        // guard edges: a 2-byte option (unknown kind, no data) walks
        // clean; rr with an off-grid 5-byte address tail (the
        // `&&`→`||` boundary — ptr types, route does not); rr with a
        // 2-byte body (ptr + 1 tail byte — no full address); ts with a
        // 1-byte body; ts stamps off-grid — kind/len/raw only, the
        // typed fields stay absent.
        for (hex, typed) in [
            ("hex:1902", "opt.0.ptr"), // 2-byte option: walks clean, no typed fields
            ("hex:0708040102030405", "opt.0.route"), // rr, addrs len 5 (off-grid)
            ("hex:07040405", "opt.0.ptr"), // rr, data = ptr + 1 byte
            ("hex:44030100", "opt.0.ts_flag"), // ts, data = ptr + pad
            ("hex:4407010203040500", "opt.0.ts"), // ts, stamps len 3 (off-grid)
        ] {
            let hex = hex.replace(' ', "");
            let spec = ip_spec(&[("options", hex.as_str())]);
            let enc = encode(
                &registry(),
                &PacketSpec::new(vec![spec], None),
                &EncodeOpts::default(),
            )
            .unwrap();
            let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "ipv4");
            assert!(p.anomalies.is_empty(), "{hex}: {:?}", p.anomalies);
            assert!(
                !p.layers[0].fields.contains_key(typed),
                "{hex}: {typed} must stay absent (the guard did not fire)"
            );
        }
    }

    /// Craft-side edge pins: the raw cap (253 ok / 254 the pointed
    /// error), a 2-byte record carrying an explicit len (nop-only —
    /// route options are ≥7), and the eol/nop wire pins.
    #[test]
    fn record_craft_edge_pins() {
        let mut big = String::with_capacity(253 * 2);
        big.push_str("hex:");
        for _ in 0..253 {
            big.push_str("aa");
        }
        let spec = ip_spec(&[("opt.0.kind", "25"), ("opt.0.raw", &big)]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts::default(),
        )
        .expect("253 fits");
        assert_eq!(enc.bytes.len(), 20 + 256); // 255 + one pad byte
        let mut bigger = String::with_capacity(254 * 2);
        bigger.push_str("hex:");
        for _ in 0..254 {
            bigger.push_str("aa");
        }
        let spec = ip_spec(&[("opt.0.kind", "25"), ("opt.0.raw", &bigger)]);
        assert!(
            encode(
                &registry(),
                &PacketSpec::new(vec![spec], None),
                &EncodeOpts::default()
            )
            .is_err()
        );
        // the 2-byte record (unknown kind, empty raw) carries an
        // explicit len — the `<` boundary in the explicit-len check.
        let spec = ip_spec(&[("opt.0.kind", "25"), ("opt.0.len", "3")]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts::default(),
        )
        .unwrap();
        assert_eq!(&enc.bytes[20..22], &[25, 3][..]); // verbatim, unvalidated
        // …and a >2-byte record rides it too (the `<`→`>` boundary).
        let spec = ip_spec(&[
            ("opt.0.kind", "ts"),
            ("opt.0.ts_flag", "1"),
            ("opt.0.ts", "0x11223344"),
            ("opt.0.len", "8"),
        ]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts::default(),
        )
        .unwrap();
        assert_eq!(enc.bytes[21], 8); // verbatim, unvalidated
        // eol/nop wire pins: kind byte ONLY (a deleted arm leaks a len).
        let spec = ip_spec(&[("opt.0.kind", "eol")]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts::default(),
        )
        .unwrap();
        assert_eq!(&enc.bytes[20..24], &[0, 0, 0, 0][..]);
        let spec = ip_spec(&[("opt.0.kind", "nop")]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts::default(),
        )
        .unwrap();
        assert_eq!(&enc.bytes[20..24], &[1, 0, 0, 0][..]);
    }
}
