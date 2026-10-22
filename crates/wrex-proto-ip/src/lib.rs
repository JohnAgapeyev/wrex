#![forbid(unsafe_code)]
//! wrex IPv4 codec (ver/ihl/tos/total_len/id/flags/frag_off/ttl/proto/
//! checksum/src/dst/options; rank 20, parent eth; also a valid stack start).

mod options;

use std::sync::LazyLock;

use bytes::{BufMut, Bytes};
use std::net::Ipv4Addr;

use wrex_core::dissect::{LayerView, NetFacts};
use wrex_core::encode::{EncodeCtx, Patch, flagset_or_default, int_or_default, ipv4_or_default};
use wrex_core::error::DecodeError;
use wrex_core::schema::{
    ChecksumEnd, Derived, FieldKind, FieldSchema, LayerSchema, Layout, LengthBase, PseudoSource,
};
use wrex_core::spec::LayerSpec;
use wrex_core::value::Value;
use wrex_core::{Anomaly, Codec, DecodeCtx, EncodeError, Next, ReadOutcome};

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
            bit_names: &["df", "mf"],
            default: Value::Int(0),
            required: false,
            doc: "flags aggregate [df,mf]; per-bit subpaths flags.df / flags.mf",
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
            doc: "options: eol,nop,rr:IP…,ssrr:IP…,lsrr:IP…,ts:FLAG,CNT, or hex:…",
        },
    ]
});

/// The kind string this codec implements (ADR 3): children (icmp,
/// udp, tcp) reference `wrex_proto_ip::KIND` in their `parents`
/// instead of hand-written strings, so the registry vocabulary is
/// compile-checked.
pub const KIND: &str = "ipv4";

pub static SCHEMA: LazyLock<LayerSchema> = LazyLock::new(|| LayerSchema {
    kind: KIND,
    rank: 20,
    parents: &[wrex_proto_eth::KIND, wrex_proto_vlan::KIND],
    doc: "IPv4 (RFC 791). Also a valid stack start. ver=4, ihl derived from options length (explicit ihl wins; invalid values are kept and flagged only under --strict), total_len and checksum autofilled from the packet (explicit values win). proto drives the chain: 1=icmp, 6=tcp, 17=udp, else synthesized `unknown`. Stacks on eth or vlan (802.1Q tag). options grammar: eol,nop,rr:IP,ssrr:IP,lsrr:IP,ts:FLAG,CNT, or hex:BYTES. CLI alias: `ip` (--ip-ttl == --ipv4-ttl).",
    fields: FIELDS.as_slice(),
    records: &[],
});

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

/// next layer kind → protocol number.
fn kind_to_proto(kind: Option<&'static str>) -> u8 {
    match kind {
        Some("icmp") => 1,
        Some("tcp") => 6,
        Some("udp") => 17,
        _ => 0,
    }
}

/// protocol number → next layer kind.
fn proto_to_kind(p: u8) -> &'static str {
    match p {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        _ => "unknown",
    }
}

/// Options bytes for a spec: `Value::Str` (list grammar) or `Value::Bytes`
/// (raw), zero-padded to a 4-byte multiple.
fn options_region(spec: &LayerSpec) -> Result<Vec<u8>, EncodeError> {
    let raw = match spec.fields.get("options") {
        Some(Value::Str(s)) => options::parse_options(s)?,
        Some(Value::Bytes(b)) => b.to_vec(),
        _ => Vec::new(),
    };
    let mut raw = raw;
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

        // Flag names for the 2-bit aggregate (MSB-first: df=bit1, mf=bit0).
        let agg = (flags_frag >> 13) & 0x3;
        let mut names: Vec<Value> = Vec::new();
        if agg & 0b10 != 0 {
            names.push(Value::Str("df".into()));
        }
        if agg & 0b01 != 0 {
            names.push(Value::Str("mf".into()));
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
        ctx.facts.net = Some(NetFacts::V4 { src, dst, proto });
        let view = LayerView {
            kind: "ipv4",
            span: ctx.offset..ctx.offset + hlen,
            field_spans: Default::default(),
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
            },
            Derived::Checksum {
                field: "checksum",
                at: 10,
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
        (
            any::<u8>(),
            any::<u16>(),
            proptest::sample::select(vec![0u8, 32, 64, 255]),
            // frag_off is a 13-bit field: valid range only.
            (0u16..0x2000),
            ip.clone(),
            ip,
            opts,
        )
            .prop_map(|(tos, id, ttl, frag, src, dst, opts)| {
                let mut fields = std::collections::BTreeMap::new();
                fields.insert("tos".to_string(), Value::Int(tos as u128));
                fields.insert("id".to_string(), Value::Int(id as u128));
                fields.insert("ttl".to_string(), Value::Int(ttl as u128));
                fields.insert("frag_off".to_string(), Value::Int(frag as u128));
                fields.insert("src".to_string(), src);
                fields.insert("dst".to_string(), dst);
                if let Some(o) = opts {
                    fields.insert("options".to_string(), Value::Str(o));
                }
                LayerSpec::with_fields("ipv4", fields)
            })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use wrex_core::Registry;
    use wrex_core::dissect::DecodeCtx;
    use wrex_core::encode::{EncodeOpts, encode};
    use wrex_core::spec::PacketSpec;
    use wrex_core::value::parse_value;

    fn f(name: &str) -> &'static FieldSchema {
        SCHEMA.field(name).unwrap()
    }

    fn ip_spec(fields: &[(&str, &str)]) -> LayerSpec {
        let mut map = BTreeMap::new();
        for (k, v) in fields {
            if *k == "options" {
                // Options use the list grammar, not the Bytes value grammar.
                map.insert(k.to_string(), Value::Str((*v).to_string()));
                continue;
            }
            map.insert(k.to_string(), parse_value(f(k), v).unwrap());
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
}
