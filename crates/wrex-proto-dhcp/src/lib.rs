#![forbid(unsafe_code)]
//! wrex DHCP codec (RFC 2131 fixed header + RFC 2132 option TLVs;
//! rank 40, parent udp).
//!
//! Port-67/68 datagrams chain into this codec from udp (the
//! tranche-3 port-dispatch pattern). The fixed 240-byte header is fully
//! craftable (`op`/`htype`/`hlen`/`hops`/`xid`/`secs`/`flags`/
//! `ciaddr`/`yiaddr`/`siaddr`/`giaddr`/`chaddr`/`sname`/`file`/
//! `cookie`); `msg_type` is the hoisted option 53 (dns opcode/rcode
//! precedent — craft accepts `discover|…|inform` or 1-8 and writes the
//! TLV, dissection hoists it back so filters work regardless of option
//! order). The options region is craftable through the `options` list
//! grammar (`--dhcp-options`, a `FieldKind::Str` field so the grammar
//! is CLI-reachable — see `options` module) plus a raw `hex:` escape;
//! craft always appends the `end` (255) marker.
//!
//! Dissection renders every option as an indexed record of the
//! dissect-only `opt` section: `opt.N.code`, `opt.N.len`,
//! `opt.N.value` (raw hex, the wire truth) plus a typed subset per
//! code — `ip` (Ipv4: subnet mask/requested ip/server id; the first
//! address of routers/dns), `num` (Int: message type/lease/renew/
//! rebind/max message size), `text` (Str: host/domain name). A wrong
//! magic cookie is a never-fatal anomaly: the layer stops at the fixed
//! header and the BOOTP vend fields stay payload.
//!
//! Tranche-7c deferrals: DHCPv6 (546/547 — a different protocol),
//! CLI-settable indexed option records (`opt` is dissect-only, the
//! dns an/ns/ar precedent), deeper option typing beyond the committed
//! grammar surface (raw `hex:CODE:HEX` covers the rest), relay/sname
//! overload semantics.

pub mod options;

use std::net::Ipv4Addr;
use std::sync::LazyLock;

use bytes::{BufMut, Bytes};
use wrex_core::dissect::LayerView;
use wrex_core::encode::{EncodeCtx, flagset_or_default, int_or_default, ipv4_or_default};
use wrex_core::error::DecodeError;
use wrex_core::schema::{FieldKind, FieldSchema, LayerSchema, RecordSchema};
use wrex_core::spec::LayerSpec;
use wrex_core::value::Value;
use wrex_core::{Anomaly, Codec, DecodeCtx, EncodeError, Next, ReadOutcome};

use crate::options::{
    OPT_ADDRESS_TIME, OPT_DNS_SERVERS, OPT_DOMAIN_NAME, OPT_END, OPT_HOST_NAME, OPT_MAX_MSG_SIZE,
    OPT_MSG_TYPE, OPT_PAD, OPT_REBINDING_TIME, OPT_RENEWAL_TIME, OPT_REQUESTED_IP, OPT_ROUTER,
    OPT_SERVER_ID, OPT_SUBNET_MASK, parse_msg_type, parse_options, render_msg_type, scan_msg_type,
};

/// The RFC 2131 fixed header: 4 op bytes + xid + secs/flags + 4
/// addresses + chaddr + sname + file + the magic cookie.
pub const HEADER_LEN: usize = 240;

/// The DHCP magic cookie (RFC 2131 §3.1: 99.130.83.99).
pub const MAGIC_COOKIE: u32 = 0x6382_5363;

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
            "op",
            FieldKind::U8,
            "message op: 1 BOOTREQUEST (client), 2 BOOTREPLY (server) (autofill: 1)",
            Value::Int(1),
        ),
        d(
            "htype",
            FieldKind::U8,
            "hardware address type (autofill: 1 ethernet)",
            Value::Int(1),
        ),
        d(
            "hlen",
            FieldKind::U8,
            "hardware address length (autofill: 6)",
            Value::Int(6),
        ),
        d(
            "hops",
            FieldKind::U8,
            "relay hop count (autofill: 0)",
            Value::Int(0),
        ),
        d(
            "xid",
            FieldKind::U32,
            "transaction id (autofill: 0, deterministic)",
            Value::Int(0),
        ),
        d(
            "secs",
            FieldKind::U16,
            "seconds since client boot",
            Value::Int(0),
        ),
        FieldSchema {
            name: "flags",
            kind: FieldKind::FlagSet,
            bit_names: &["broadcast"],
            default: Value::Int(0),
            required: false,
            doc: "flag aggregate [broadcast] (0x8000); subpath flags.broadcast",
        },
        d(
            "ciaddr",
            FieldKind::Ipv4,
            "client IP address",
            Value::Ipv4(Ipv4Addr::UNSPECIFIED),
        ),
        d(
            "yiaddr",
            FieldKind::Ipv4,
            "your (client) IP address",
            Value::Ipv4(Ipv4Addr::UNSPECIFIED),
        ),
        d(
            "siaddr",
            FieldKind::Ipv4,
            "server IP address",
            Value::Ipv4(Ipv4Addr::UNSPECIFIED),
        ),
        d(
            "giaddr",
            FieldKind::Ipv4,
            "gateway/relay IP address",
            Value::Ipv4(Ipv4Addr::UNSPECIFIED),
        ),
        d(
            "chaddr",
            FieldKind::Bytes,
            "client hardware address (up to 16 bytes, zero-padded)",
            Value::Bytes(Bytes::new()),
        ),
        d(
            "sname",
            FieldKind::Str,
            "server host name (NUL-padded to 64; dissection trims at the first NUL)",
            Value::Str(String::new()),
        ),
        d(
            "file",
            FieldKind::Str,
            "boot file name (NUL-padded to 128; dissection trims at the first NUL)",
            Value::Str(String::new()),
        ),
        d(
            "cookie",
            FieldKind::U32,
            "magic cookie (autofill: 0x63825363)",
            Value::Int(MAGIC_COOKIE as u128),
        ),
        d(
            "msg_type",
            FieldKind::Str,
            "DHCP message type, the hoisted option 53: discover|offer|request|decline|ack|nak|release|inform or 1-8 (mutually exclusive with type: in --dhcp-options)",
            Value::Str(String::new()),
        ),
        d(
            "options",
            FieldKind::Str,
            "options list grammar: type:N, mask:IP, routers:IP…, dns:IP…, host:NAME, domain:NAME, req_ip:IP, lease:SECS, renew:SECS, rebind:SECS, server:IP, param_req:N…, max_msg:N, client_id:HEX, pad, hex:CODE:HEX (end marker appended automatically)",
            Value::Str(String::new()),
        ),
    ]
});

static OPT_FIELDS: LazyLock<Vec<FieldSchema>> = LazyLock::new(|| {
    vec![
        d(
            "code",
            FieldKind::U8,
            "option code (RFC 2132; 53 = message type)",
            Value::Int(0),
        ),
        d(
            "len",
            FieldKind::U8,
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
            FieldKind::Ipv4,
            "typed address: subnet mask (1), requested ip (50), server id (54); first address of routers (3) / dns servers (6)",
            Value::Ipv4(Ipv4Addr::UNSPECIFIED),
        ),
        d(
            "num",
            FieldKind::U32,
            "typed number: message type (53), lease (51), renewal (58), rebinding (59), max message size (57)",
            Value::Int(0),
        ),
        d(
            "text",
            FieldKind::Str,
            "typed string: host name (12), domain name (15)",
            Value::Str(String::new()),
        ),
    ]
});

static RECORDS: LazyLock<Vec<RecordSchema>> = LazyLock::new(|| {
    vec![RecordSchema {
        name: "opt",
        fields: OPT_FIELDS.as_slice(),
        settable: false,
        max: None,
        doc: "DHCP option TLVs after the magic cookie (dissect-only; indexed paths opt.0.code, opt.0.value, …)",
    }]
});

pub static SCHEMA: LazyLock<LayerSchema> = LazyLock::new(|| LayerSchema {
    kind: "dhcp",
    rank: 40,
    parents: &["udp"],
    doc: "DHCP (RFC 2131) over UDP 67/68: the 240-byte fixed header (op/htype/hlen/hops, xid, secs, flags [broadcast], ciaddr/yiaddr/siaddr/giaddr, chaddr, sname, file, cookie) plus RFC 2132 option TLVs. Craft: --dhcp-msg_type writes option 53 (discover|…|inform or 1-8; underscore flags follow the codebase convention like --tcp-data_off), --dhcp-options takes the list grammar (type:, mask:, routers:IP…, dns:IP…, host:, domain:, req_ip:, lease:, renew:, rebind:, server:, param_req:N…, max_msg:, client_id:HEX, pad, hex:CODE:HEX) and the end marker is appended automatically. Dissect: every option lands in the dissect-only opt record section (opt.0.code/len/value raw + typed ip/num/text subset); a wrong magic cookie is a never-fatal anomaly and stops the layer at the fixed header (BOOTP legacy — vend fields stay payload). udp dispatches ports 67/68 into this codec. DHCPv6 and CLI-settable option records are tranche-7c deferrals.",
    fields: FIELDS.as_slice(),
    records: RECORDS.as_slice(),
});

/// DHCP codec unit. Register as `&wrex_proto_dhcp::CODEC`.
pub struct DhcpCodec;

pub static CODEC: DhcpCodec = DhcpCodec;

/// Options region for a spec: the parsed list grammar (Str) or the
/// raw bytes (Bytes). The hoisted `msg_type` TLV is separate — the
/// mutual-exclusion guard scans this region for a stray 53.
fn grammar_region(spec: &LayerSpec) -> Result<Vec<u8>, EncodeError> {
    match spec.fields.get("options") {
        Some(Value::Str(raw)) => parse_options(raw),
        Some(Value::Bytes(b)) => Ok(b.to_vec()),
        _ => Ok(Vec::new()),
    }
}

/// The hoisted option-53 TLV bytes for a spec (`msg_type` set), plus
/// `None` when unset.
fn msg_type_tlv(spec: &LayerSpec) -> Result<Option<[u8; 3]>, EncodeError> {
    match spec.fields.get("msg_type") {
        Some(Value::Str(mt)) if !mt.is_empty() => {
            let n = parse_msg_type(mt).ok_or_else(|| EncodeError::IncompatibleStack {
                detail: format!("dhcp.msg_type: unknown message type `{mt}`"),
            })?;
            Ok(Some([OPT_MSG_TYPE, 1, n]))
        }
        _ => Ok(None),
    }
}

/// Write `bytes` NUL-padded to `width` (truncated beyond it).
fn put_padded(buf: &mut bytes::BytesMut, bytes: &[u8], width: usize) {
    let take = bytes.len().min(width);
    buf.extend_from_slice(&bytes[..take]);
    buf.extend(std::iter::repeat_n(0u8, width - take));
}

/// NUL-terminated string field out of a fixed-width region.
fn str_until_nul(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

impl Codec for DhcpCodec {
    fn schema(&self) -> &'static LayerSchema {
        &SCHEMA
    }

    fn header_len(&self, spec: &LayerSpec) -> Result<usize, EncodeError> {
        // Fixed header + msg-type TLV + options region + end marker.
        let msg = msg_type_tlv(spec)?.map_or(0, |t| t.len());
        Ok(HEADER_LEN + msg + grammar_region(spec)?.len() + 1)
    }

    fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
        let af = ctx.autofill;
        let bad = |detail: String| EncodeError::IncompatibleStack { detail };
        let f = |name: &str| SCHEMA.field(name).expect("field in schema");

        ctx.buf.put_u8(int_or_default(spec, f("op"), af) as u8);
        ctx.buf.put_u8(int_or_default(spec, f("htype"), af) as u8);
        ctx.buf.put_u8(int_or_default(spec, f("hlen"), af) as u8);
        ctx.buf.put_u8(int_or_default(spec, f("hops"), af) as u8);
        ctx.buf.put_u32(int_or_default(spec, f("xid"), af) as u32);
        ctx.buf.put_u16(int_or_default(spec, f("secs"), af) as u16);
        // [broadcast] is a 1-bit aggregate (broadcast = bit 0) placed at
        // the top of the flags word (0x8000).
        let agg = flagset_or_default(spec, f("flags"), af) as u16;
        ctx.buf.put_u16((agg & 1) << 15);
        for name in ["ciaddr", "yiaddr", "siaddr", "giaddr"] {
            let addr = ipv4_or_default(spec, f(name), af);
            ctx.buf.extend_from_slice(&addr.octets());
        }
        // chaddr: up to 16 bytes, zero-padded.
        let chaddr = match spec.fields.get("chaddr") {
            Some(Value::Bytes(b)) => b.to_vec(),
            _ => Vec::new(),
        };
        put_padded(ctx.buf, &chaddr, 16);
        // sname/file: NUL-padded fixed-width strings.
        let sname = match spec.fields.get("sname") {
            Some(Value::Str(s)) => s.as_bytes().to_vec(),
            _ => Vec::new(),
        };
        put_padded(ctx.buf, &sname, 64);
        let file = match spec.fields.get("file") {
            Some(Value::Str(s)) => s.as_bytes().to_vec(),
            _ => Vec::new(),
        };
        put_padded(ctx.buf, &file, 128);
        ctx.buf
            .put_u32(int_or_default(spec, f("cookie"), af) as u32);

        // Options region: the hoisted msg_type TLV first, then the
        // grammar/raw region, then the end marker. Setting msg_type AND
        // a `type:` option would emit option 53 twice — a usage error.
        let region = grammar_region(spec)?;
        if let Some(tlv) = msg_type_tlv(spec)? {
            if scan_msg_type(&region) {
                return Err(bad(
                    "dhcp.msg_type and type: in --dhcp-options are mutually exclusive".to_string(),
                ));
            }
            ctx.buf.extend_from_slice(&tlv);
        }
        ctx.buf.extend_from_slice(&region);
        ctx.buf.put_u8(OPT_END);
        Ok(())
    }

    fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
        if bytes.is_empty() {
            return ReadOutcome::Empty;
        }
        if bytes.len() < HEADER_LEN {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: "dhcp",
                    need: HEADER_LEN,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }

        let mut fields = std::collections::BTreeMap::new();
        fields.insert("op".into(), Value::Int(bytes[0] as u128));
        fields.insert("htype".into(), Value::Int(bytes[1] as u128));
        fields.insert("hlen".into(), Value::Int(bytes[2] as u128));
        fields.insert("hops".into(), Value::Int(bytes[3] as u128));
        fields.insert(
            "xid".into(),
            Value::Int(u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as u128),
        );
        fields.insert(
            "secs".into(),
            Value::Int(u16::from_be_bytes([bytes[8], bytes[9]]) as u128),
        );
        let flags = u16::from_be_bytes([bytes[10], bytes[11]]);
        let mut names: Vec<Value> = Vec::new();
        if flags & 0x8000 != 0 {
            names.push(Value::Str("broadcast".into()));
        }
        fields.insert("flags".into(), Value::List(names));
        for (i, name) in ["ciaddr", "yiaddr", "siaddr", "giaddr"].iter().enumerate() {
            let at = 12 + i * 4;
            fields.insert(
                (*name).into(),
                Value::Ipv4(Ipv4Addr::new(
                    bytes[at],
                    bytes[at + 1],
                    bytes[at + 2],
                    bytes[at + 3],
                )),
            );
        }
        fields.insert(
            "chaddr".into(),
            Value::Bytes(Bytes::copy_from_slice(&bytes[28..44])),
        );
        fields.insert("sname".into(), Value::Str(str_until_nul(&bytes[44..108])));
        fields.insert("file".into(), Value::Str(str_until_nul(&bytes[108..236])));
        let cookie = u32::from_be_bytes([bytes[236], bytes[237], bytes[238], bytes[239]]);
        fields.insert("cookie".into(), Value::Int(cookie as u128));

        // BOOTP legacy: no magic cookie → the layer stops at the fixed
        // header (never fatal; vend fields stay payload).
        if cookie != MAGIC_COOKIE {
            ctx.anomalies.push(Anomaly::new(
                "dhcp.cookie",
                format!("expected 0x{MAGIC_COOKIE:08x}, found 0x{cookie:08x} (BOOTP legacy — options not parsed)"),
            ));
            let view = LayerView {
                kind: "dhcp",
                span: ctx.offset..ctx.offset + HEADER_LEN,
                field_spans: Default::default(),
                fields,
            };
            return ReadOutcome::Layer(view, Some(Next::Payload));
        }

        // Option TLVs: pad (0) skipped, end (255) stops the walk; an
        // option overrunning the region stops with a never-fatal
        // anomaly (the rest stays payload).
        let mut consumed = bytes.len();
        let mut cursor = HEADER_LEN;
        let mut i = 0usize;
        let mut hoisted = false;
        while cursor < bytes.len() {
            let code = bytes[cursor];
            if code == OPT_PAD {
                cursor += 1;
                consumed = cursor;
                continue;
            }
            if code == OPT_END {
                consumed = cursor + 1;
                break;
            }
            if cursor + 2 > bytes.len() {
                // dangling option header byte: lenient stop, the rest
                // stays payload
                consumed = cursor;
                break;
            }
            let olen = bytes[cursor + 1] as usize;
            if cursor + 2 + olen > bytes.len() {
                ctx.anomalies.push(Anomaly::new(
                    format!("dhcp.opt.{i}"),
                    format!("option overruns the message (code {code}, need {olen} bytes)"),
                ));
                consumed = cursor;
                break;
            }
            let data = &bytes[cursor + 2..cursor + 2 + olen];
            fields.insert(format!("opt.{i}.code"), Value::Int(code as u128));
            fields.insert(format!("opt.{i}.len"), Value::Int(olen as u128));
            fields.insert(
                format!("opt.{i}.value"),
                Value::Bytes(Bytes::copy_from_slice(data)),
            );
            // Typed subset per code (never fatal on bad lengths).
            match code {
                OPT_MSG_TYPE if !data.is_empty() => {
                    fields.insert(format!("opt.{i}.num"), Value::Int(data[0] as u128));
                    if !hoisted {
                        hoisted = true;
                        fields.insert("msg_type".into(), Value::Str(render_msg_type(data[0])));
                    }
                }
                OPT_SUBNET_MASK | OPT_REQUESTED_IP | OPT_SERVER_ID if olen == 4 => {
                    fields.insert(
                        format!("opt.{i}.ip"),
                        Value::Ipv4(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
                    );
                }
                // Multi-address options: `ip` is the first address.
                OPT_ROUTER | OPT_DNS_SERVERS if olen >= 4 && olen.is_multiple_of(4) => {
                    fields.insert(
                        format!("opt.{i}.ip"),
                        Value::Ipv4(Ipv4Addr::new(data[0], data[1], data[2], data[3])),
                    );
                }
                OPT_ADDRESS_TIME | OPT_RENEWAL_TIME | OPT_REBINDING_TIME if olen == 4 => {
                    fields.insert(
                        format!("opt.{i}.num"),
                        Value::Int(u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as u128),
                    );
                }
                OPT_MAX_MSG_SIZE if olen == 2 => {
                    fields.insert(
                        format!("opt.{i}.num"),
                        Value::Int(u16::from_be_bytes([data[0], data[1]]) as u128),
                    );
                }
                OPT_HOST_NAME | OPT_DOMAIN_NAME => {
                    fields.insert(
                        format!("opt.{i}.text"),
                        Value::Str(String::from_utf8_lossy(data).into_owned()),
                    );
                }
                _ => {}
            }
            i += 1;
            cursor += 2 + olen;
            consumed = cursor;
        }

        let view = LayerView {
            kind: "dhcp",
            span: ctx.offset..ctx.offset + consumed,
            field_spans: Default::default(),
            fields,
        };
        // Terminal: post-`end` bytes are padding/payload.
        ReadOutcome::Layer(view, Some(Next::Payload))
    }
}

#[cfg(feature = "test-util")]
pub mod strategy {
    //! proptest strategies for `LayerSpec` (behind `test-util`).
    use proptest::prelude::*;
    use wrex_core::spec::LayerSpec;
    use wrex_core::value::Value;

    use crate::options::MSG_TYPES;

    /// Valid dhcp specs: random identities/addresses, a message type
    /// from the canonical names (roundtrips exact), and a small valid
    /// options-grammar pool. `flags`/`chaddr`/`cookie` stay unset (the
    /// differential roundtrip compares set fields only; chaddr pads to
    /// 16 bytes on the wire).
    pub fn strategy() -> BoxedStrategy<LayerSpec> {
        let ip = any::<u32>().prop_map(|v| Value::Ipv4(std::net::Ipv4Addr::from(v)));
        let msg_type = proptest::sample::select(
            MSG_TYPES
                .iter()
                .map(|(n, _)| Value::Str(n.to_string()))
                .collect::<Vec<_>>(),
        );
        let sname = proptest::option::of(
            proptest::sample::select(vec!["wrex-server".to_string()]).prop_map(Value::Str),
        );
        let file = proptest::option::of(
            proptest::sample::select(vec!["boot.img".to_string()]).prop_map(Value::Str),
        );
        let opts = proptest::option::of(
            proptest::sample::select(vec![
                "mask:255.255.255.0,routers:10.0.0.1".to_string(),
                "lease:3600,renew:1500,rebind:2700".to_string(),
                "host:wrex,req_ip:192.0.2.10".to_string(),
                "dns:10.0.0.53,param_req:1,3,6".to_string(),
                "client_id:hex:010203040506".to_string(),
                "server:10.0.0.1,max_msg:1500".to_string(),
                "hex:82:0105dc,pad".to_string(),
                "".to_string(),
            ])
            .prop_map(Value::Str),
        );
        (
            any::<u32>(), // xid
            any::<u16>(), // secs
            ip.clone(),   // ciaddr
            ip.clone(),   // yiaddr
            ip.clone(),   // siaddr
            ip,           // giaddr
            msg_type,
            sname,
            file,
            opts,
        )
            .prop_map(
                |(xid, secs, ciaddr, yiaddr, siaddr, giaddr, msg_type, sname, file, opts)| {
                    let mut fields = std::collections::BTreeMap::new();
                    fields.insert("op".to_string(), Value::Int(1));
                    fields.insert("htype".to_string(), Value::Int(1));
                    fields.insert("hlen".to_string(), Value::Int(6));
                    fields.insert("xid".to_string(), Value::Int(xid as u128));
                    fields.insert("secs".to_string(), Value::Int(secs as u128));
                    fields.insert("ciaddr".to_string(), ciaddr);
                    fields.insert("yiaddr".to_string(), yiaddr);
                    fields.insert("siaddr".to_string(), siaddr);
                    fields.insert("giaddr".to_string(), giaddr);
                    fields.insert("msg_type".to_string(), msg_type);
                    if let Some(s) = sname {
                        fields.insert("sname".to_string(), s);
                    }
                    if let Some(fi) = file {
                        fields.insert("file".to_string(), fi);
                    }
                    if let Some(o) = opts {
                        if matches!(&o, Value::Str(s) if s.is_empty()) {
                            // the empty-grammar sample is the no-options case
                        } else {
                            fields.insert("options".to_string(), o);
                        }
                    }
                    LayerSpec::with_fields("dhcp", fields)
                },
            )
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use wrex_core::Registry;
    use wrex_core::encode::{EncodeOpts, encode};
    use wrex_core::spec::PacketSpec;
    use wrex_core::value::parse_value;

    fn f(name: &str) -> &'static FieldSchema {
        SCHEMA.field(name).unwrap()
    }

    fn registry() -> Registry {
        let mut r = Registry::empty();
        r.register(&CODEC);
        r
    }

    fn af() -> EncodeOpts {
        EncodeOpts {
            autofill: true,
            ..Default::default()
        }
    }

    fn dhcp_spec(fields: &[(&str, &str)]) -> LayerSpec {
        let mut map = BTreeMap::new();
        for (k, v) in fields {
            map.insert(k.to_string(), parse_value(f(k), v).unwrap());
        }
        LayerSpec::with_fields("dhcp", map)
    }

    #[test]
    fn golden_fixed_header() {
        let spec = dhcp_spec(&[("xid", "0x11223344"), ("yiaddr", "192.0.2.10")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &af()).unwrap();
        assert_eq!(enc.bytes.len(), 241); // 240 + end
        assert_eq!(enc.bytes[0], 1); // op BOOTREQUEST
        assert_eq!(enc.bytes[1], 1); // htype ethernet
        assert_eq!(enc.bytes[2], 6); // hlen
        assert_eq!(
            u32::from_be_bytes(enc.bytes[4..8].try_into().unwrap()),
            0x11223344
        );
        assert_eq!(&enc.bytes[16..20], &[192, 0, 2, 10]);
        // chaddr/sname/file zero regions
        assert_eq!(&enc.bytes[28..236], &[0u8; 208][..]);
        assert_eq!(
            u32::from_be_bytes(enc.bytes[236..240].try_into().unwrap()),
            MAGIC_COOKIE
        );
        assert_eq!(enc.bytes[240], 255); // end marker
        // dissect back: no anomalies, fields roundtrip
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "dhcp");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.layers[0].fields.get("xid"), Some(&Value::Int(0x11223344)));
        assert_eq!(
            p.layers[0].fields.get("yiaddr"),
            Some(&Value::Ipv4("192.0.2.10".parse().unwrap()))
        );
        assert_eq!(
            p.layers[0].fields.get("cookie"),
            Some(&Value::Int(MAGIC_COOKIE as u128))
        );
    }

    #[test]
    fn sname_file_padding_and_trim() {
        let spec = dhcp_spec(&[("sname", "wrex-server"), ("file", "boot.img")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &af()).unwrap();
        assert_eq!(&enc.bytes[44..55], b"wrex-server");
        assert_eq!(enc.bytes[55], 0); // NUL-padded to 64
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "dhcp");
        assert_eq!(
            p.layers[0].fields.get("sname"),
            Some(&Value::Str("wrex-server".into()))
        );
        assert_eq!(
            p.layers[0].fields.get("file"),
            Some(&Value::Str("boot.img".into()))
        );
        // golden fixed header elsewhere: all-NUL regions dissect to ""
        let spec = dhcp_spec(&[]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &af()).unwrap();
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "dhcp");
        assert_eq!(
            p.layers[0].fields.get("sname"),
            Some(&Value::Str(String::new()))
        );
        assert_eq!(
            p.layers[0].fields.get("file"),
            Some(&Value::Str(String::new()))
        );
    }

    #[test]
    fn msg_type_hoist_write_and_read() {
        let spec = dhcp_spec(&[("msg_type", "discover")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &af()).unwrap();
        // msg_type TLV first in the region
        assert_eq!(&enc.bytes[240..244], &[53, 1, 1, 255]);
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "dhcp");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(
            p.layers[0].fields.get("msg_type"),
            Some(&Value::Str("discover".into()))
        );
        assert_eq!(p.layers[0].fields.get("opt.0.code"), Some(&Value::Int(53)));
        assert_eq!(p.layers[0].fields.get("opt.0.num"), Some(&Value::Int(1)));
        assert!(p.payload.is_empty());
        // numeric spelling + ack reply shape
        let spec = dhcp_spec(&[("msg_type", "5"), ("op", "2")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &af()).unwrap();
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "dhcp");
        assert_eq!(
            p.layers[0].fields.get("msg_type"),
            Some(&Value::Str("ack".into()))
        );
    }

    #[test]
    fn msg_type_and_type_token_conflict() {
        let spec = dhcp_spec(&[("msg_type", "discover"), ("options", "type:offer")]);
        assert!(encode(&registry(), &PacketSpec::new(vec![spec], None), &af()).is_err());
    }

    #[test]
    fn options_grammar_records() {
        let spec = dhcp_spec(&[
            ("msg_type", "request"),
            (
                "options",
                "req_ip:192.0.2.50,lease:3600,server:10.0.0.1,routers:10.0.0.1,10.0.0.2,host:wrex,param_req:1,3,6,client_id:hex:010203040506",
            ),
        ]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &af()).unwrap();
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "dhcp");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        let fl = &p.layers[0].fields;
        // order: msg_type (53) first, then the grammar order
        assert_eq!(fl.get("opt.0.code"), Some(&Value::Int(53)));
        assert_eq!(fl.get("opt.1.code"), Some(&Value::Int(50)));
        assert_eq!(
            fl.get("opt.1.ip"),
            Some(&Value::Ipv4("192.0.2.50".parse().unwrap()))
        );
        assert_eq!(fl.get("opt.2.code"), Some(&Value::Int(51)));
        assert_eq!(fl.get("opt.2.num"), Some(&Value::Int(3600)));
        assert_eq!(
            fl.get("opt.3.ip"),
            Some(&Value::Ipv4("10.0.0.1".parse().unwrap()))
        );
        // routers: first address in `ip`, both in `value`
        assert_eq!(fl.get("opt.4.code"), Some(&Value::Int(3)));
        assert_eq!(
            fl.get("opt.4.ip"),
            Some(&Value::Ipv4("10.0.0.1".parse().unwrap()))
        );
        match fl.get("opt.4.value") {
            Some(Value::Bytes(b)) => assert_eq!(&b[..], &[10, 0, 0, 1, 10, 0, 0, 2]),
            other => panic!("value: {other:?}"),
        }
        assert_eq!(fl.get("opt.5.text"), Some(&Value::Str("wrex".into())));
        assert_eq!(fl.get("opt.6.code"), Some(&Value::Int(55)));
        match fl.get("opt.6.value") {
            Some(Value::Bytes(b)) => assert_eq!(&b[..], &[1, 3, 6]),
            other => panic!("value: {other:?}"),
        }
        assert_eq!(fl.get("opt.7.code"), Some(&Value::Int(61)));
        assert!(fl.get("opt.7.ip").is_none());
        assert!(fl.get("opt.7.text").is_none());
        // value raw is always present
        assert!(matches!(fl.get("opt.7.value"), Some(Value::Bytes(_))));
        assert!(p.payload.is_empty());
    }

    #[test]
    fn post_end_padding_is_payload() {
        let spec = dhcp_spec(&[("msg_type", "release")]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(
                vec![spec],
                Some(Value::Bytes(Bytes::from_static(&[0u8; 8]))),
            ),
            &af(),
        )
        .unwrap();
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "dhcp");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.layers[0].span.end, 244); // through the end marker
        assert_eq!(p.payload.len(), 8); // padding after end stays payload
    }

    #[test]
    fn bad_cookie_bootp_legacy() {
        let spec = dhcp_spec(&[("cookie", "0xdeadbeef"), ("msg_type", "discover")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &af()).unwrap();
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "dhcp");
        // layer still dissects (never fatal), one cookie anomaly, no opt records
        assert_eq!(p.layers[0].kind, "dhcp");
        assert_eq!(p.layers[0].span.end, 240);
        assert!(
            p.anomalies.iter().any(|a| a.path == "dhcp.cookie"),
            "{:?}",
            p.anomalies
        );
        assert!(!p.layers[0].fields.contains_key("opt.0.code"));
        assert!(!p.layers[0].fields.contains_key("msg_type"));
        // the vend region (msg_type TLV + end) stays payload
        assert!(!p.payload.is_empty());
    }

    #[test]
    fn overrun_option_anomaly() {
        // hand-build: valid header + an option declaring more data than
        // present.
        let mut spec_fields = BTreeMap::new();
        spec_fields.insert("xid".to_string(), Value::Int(1));
        let mut bytes = encode(
            &registry(),
            &PacketSpec::new(vec![LayerSpec::with_fields("dhcp", spec_fields)], None),
            &af(),
        )
        .unwrap()
        .bytes
        .to_vec();
        // replace the end marker with an overrunning TLV
        bytes[240] = 61; // client id
        bytes.push(9); // 9 bytes of data — none available
        let p = wrex_core::dissect::dissect(&registry(), &bytes, "dhcp");
        assert!(
            p.anomalies.iter().any(|a| a.path == "dhcp.opt.0"),
            "{:?}",
            p.anomalies
        );
    }

    #[test]
    fn explicit_overrides_kept() {
        // cookie 0 + no options: explicit-wins keeps the zeros
        let spec = dhcp_spec(&[("cookie", "0")]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts::default(), // no autofill: defaults stay 0 too
        )
        .unwrap();
        assert_eq!(
            u32::from_be_bytes(enc.bytes[236..240].try_into().unwrap()),
            0
        );
        // broadcast flag (aggregate; the per-bit subpath lands via
        // flagset_or_default the same way)
        let spec = dhcp_spec(&[("flags", "1")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &af()).unwrap();
        assert_eq!(u16::from_be_bytes([enc.bytes[10], enc.bytes[11]]), 0x8000);
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "dhcp");
        assert_eq!(
            p.layers[0].fields.get("flags"),
            Some(&Value::List(vec![Value::Str("broadcast".into())]))
        );
    }

    #[test]
    fn truncation() {
        let mut ctx = DecodeCtx::new(0);
        assert!(matches!(
            CODEC.read(&[0xff; 239], &mut ctx),
            ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: "dhcp",
                    need: 240,
                    have: 239
                },
                _
            )
        ));
        let mut ctx = DecodeCtx::new(0);
        assert!(matches!(CODEC.read(&[], &mut ctx), ReadOutcome::Empty));
    }
}
