#![forbid(unsafe_code)]
//! wrex IPv6 codec (RFC 8200 fixed header: ver/traffic_class/flow_label/
//! payload_len/next_header/hop_limit/src/dst; rank 20, parents eth|vlan;
//! also a valid stack start).
//!
//! Extension headers are a deliberate deferral: `next_header` dispatch
//! covers icmpv6 (58), tcp (6) and udp (17) — the tranche-7b codec set —
//! everything else chains into the engine's synthesized `unknown` layer.
//! The fixed 40-byte header carries no checksum (RFC 8200 §8.1: upper
//! layers cover it, over the v6 pseudo-header).

use std::net::Ipv6Addr;
use std::sync::LazyLock;

use bytes::BufMut;

use wrex_core::dissect::{LayerView, NetFacts};
use wrex_core::encode::{EncodeCtx, Patch, int_or_default, ipv6_or_default};
use wrex_core::error::DecodeError;
use wrex_core::schema::{
    Derived, FieldKind, FieldSchema, LayerSchema, Layout, LengthBase, LengthUnits,
};
use wrex_core::spec::LayerSpec;
use wrex_core::value::Value;
use wrex_core::{Anomaly, Codec, DecodeCtx, EncodeError, Next, ReadOutcome};

/// Fixed header size (RFC 8200): no options on the base header.
pub const HEADER_LEN: usize = 40;

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
        d("ver", FieldKind::U8, "version (autofill: 6)", Value::Int(6)),
        d(
            "traffic_class",
            FieldKind::U8,
            "traffic class (top byte of the flow word)",
            Value::Int(0),
        ),
        d(
            "flow_label",
            FieldKind::U32,
            "flow label (low 20 bits of the flow word)",
            Value::Int(0),
        ),
        d(
            "payload_len",
            FieldKind::U16,
            "payload length in bytes (autofill: computed)",
            Value::Int(0),
        ),
        d(
            "next_header",
            FieldKind::U8,
            "next header (autofill: derived from next layer)",
            Value::Int(0),
        ),
        d(
            "hop_limit",
            FieldKind::U8,
            "hop limit (autofill: 64)",
            Value::Int(64),
        ),
        d(
            "src",
            FieldKind::Ipv6,
            "source address (autofill: ::1)",
            Value::Ipv6(Ipv6Addr::LOCALHOST),
        ),
        d(
            "dst",
            FieldKind::Ipv6,
            "destination address (autofill: ::1)",
            Value::Ipv6(Ipv6Addr::LOCALHOST),
        ),
    ]
});

/// The kind string this codec implements (ADR 3): children (icmpv6,
/// udp, tcp) reference `wrex_proto_ip6::KIND` in their `parents`
/// instead of hand-written strings, so the registry vocabulary is
/// compile-checked.
pub const KIND: &str = "ipv6";

pub static SCHEMA: LazyLock<LayerSchema> = LazyLock::new(|| LayerSchema {
    kind: KIND,
    rank: 20,
    parents: &[wrex_proto_eth::KIND, wrex_proto_vlan::KIND],
    doc: "IPv6 (RFC 8200) fixed 40-byte header. Also a valid stack start. ver=6, traffic_class/flow_label pack the first 32-bit word (flow_label 20 bits, explicit over-wide values masked), payload_len autofilled from the bytes after this header (explicit wins), hop_limit defaults 64. src/dst are FieldKind::Ipv6 (::1 autofill). next_header drives the chain: 58=icmpv6, 6=tcp, 17=udp, and the extension-header family (tranche 17a): 0=hopopts, 43=routing, 44=frag, 50=esp, 51=ah, 59=nonext, 60=dstopts — else synthesized `unknown`. Stacks on eth or vlan (802.1Q tag). CLI alias: `ip6`/`v6` (--ip6-hop-limit == --ipv6-hop-limit). No header checksum (RFC 8200 §8.1): upper layers checksum over the v6 pseudo-header, which covers the extension headers too (Facts::upper_start, tranche 17a).",
    fields: FIELDS.as_slice(),
    records: &[],
});

/// IPv6 codec unit. Register via [`register`] (the ADR-3 closure);
/// bespoke registries may use `&wrex_proto_ip6::CODEC` directly.
pub struct Ip6Codec;

pub static CODEC: Ip6Codec = Ip6Codec;

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

/// next layer kind → next-header number.
fn kind_to_next_header(kind: Option<&'static str>) -> u8 {
    match kind {
        Some("icmpv6") => 58,
        Some("tcp") => 6,
        Some("udp") => 17,
        // Tranche 17a: the extension-header family (craft autofill —
        // [ipv6, hopopts, …] writes next_header 0).
        Some("hopopts") => 0,
        Some("routing") => 43,
        Some("frag") => 44,
        Some("esp") => 50,
        Some("ah") => 51,
        Some("nonext") => 59,
        Some("dstopts") => 60,
        _ => 0,
    }
}

/// next-header number → next layer kind.
fn next_header_to_kind(n: u8) -> &'static str {
    match n {
        58 => "icmpv6",
        6 => "tcp",
        17 => "udp",
        // Tranche 17a: the extension-header family (wrex-proto-ip6ext —
        // dispatch stays registry strings; the child crate's
        // integration test pins this table against its own copy).
        0 => "hopopts",
        43 => "routing",
        44 => "frag",
        50 => "esp",
        51 => "ah",
        59 => "nonext",
        60 => "dstopts",
        _ => "unknown",
    }
}

impl Codec for Ip6Codec {
    fn schema(&self) -> &'static LayerSchema {
        &SCHEMA
    }

    fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
        Ok(HEADER_LEN)
    }

    fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
        let af = ctx.autofill;
        // First 32-bit word: version | traffic class | flow label.
        let ver = (int_or_default(spec, &FIELDS[0], af) as u8) & 0x0f;
        let tc = int_or_default(spec, &FIELDS[1], af) as u8;
        let flow = (int_or_default(spec, &FIELDS[2], af) as u32) & 0x0f_ffff;
        ctx.buf
            .put_u32(((ver as u32) << 28) | ((tc as u32) << 20) | flow);
        let at_payload_len = ctx.buf.len();
        let payload_len_explicit = spec.fields.contains_key("payload_len");
        if let Some(Value::Int(v)) = spec.fields.get("payload_len") {
            ctx.buf.put_u16(*v as u16);
        } else {
            ctx.buf.put_u16(0); // payload_len placeholder
        }
        let next_header = match spec.fields.get("next_header") {
            Some(Value::Int(v)) => *v as u8,
            _ if af => kind_to_next_header(ctx.next),
            _ => 0,
        };
        ctx.buf.put_u8(next_header);
        ctx.buf.put_u8(int_or_default(spec, &FIELDS[5], af) as u8); // hop_limit
        ctx.buf
            .extend_from_slice(&ipv6_or_default(spec, &FIELDS[6], af).octets());
        ctx.buf
            .extend_from_slice(&ipv6_or_default(spec, &FIELDS[7], af).octets());
        let header_end = ctx.buf.len();
        // Tranche 17a: the upper-layer packet begins here — at the
        // first extension header when one follows (RFC 8200 §8.1:
        // the L4 checksum covers the ext headers). The ext codecs
        // never touch it; the L4 checksum defers and the dissect-side
        // verify read it. Equals the L4 layer's own start on every
        // ext-free stack, so pre-17a wire bytes stay identical.
        ctx.facts.upper_start = Some(header_end);
        // payload_len covers everything after this header (base = header
        // end); the engine resolves it after the terminal payload append.
        ctx.defer(Patch::Length {
            at: at_payload_len,
            base: header_end,
            explicit: payload_len_explicit,
            path: "ipv6.payload_len",
        });
        // Record NetFacts before L4/icmpv6 writes (v6 pseudo-header source).
        wrex_core::encode::record_net_facts(
            ctx,
            NetFacts::V6 {
                src: ipv6_or_default(spec, &FIELDS[6], af),
                dst: ipv6_or_default(spec, &FIELDS[7], af),
                next_header,
            },
        );
        Ok(())
    }

    fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
        if bytes.is_empty() {
            return ReadOutcome::Empty;
        }
        if bytes.len() < HEADER_LEN {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: "ipv6",
                    need: HEADER_LEN,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let ver = (word >> 28) as u8;
        let traffic_class = ((word >> 20) & 0xff) as u8;
        let flow_label = word & 0x0f_ffff;
        let payload_len = u16::from_be_bytes([bytes[4], bytes[5]]);
        let next_header = bytes[6];
        let hop_limit = bytes[7];
        let src = Ipv6Addr::from([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);
        let dst = Ipv6Addr::from([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
            bytes[32], bytes[33], bytes[34], bytes[35], bytes[36], bytes[37], bytes[38], bytes[39],
        ]);

        // Length-vs-actual (non-fatal): payload_len covers the bytes after
        // this header.
        if payload_len != 0 && payload_len as usize + HEADER_LEN != bytes.len() {
            let actual = bytes.len().saturating_sub(HEADER_LEN);
            ctx.anomalies.push(Anomaly::new(
                "ipv6.payload_len",
                format!(
                    "mismatch (expected {payload_len} (0x{payload_len:04x}) payload bytes, found {actual})"
                ),
            ));
        }

        let mut fields = std::collections::BTreeMap::new();
        fields.insert("ver".into(), Value::Int(ver as u128));
        fields.insert("traffic_class".into(), Value::Int(traffic_class as u128));
        fields.insert("flow_label".into(), Value::Int(flow_label as u128));
        fields.insert("payload_len".into(), Value::Int(payload_len as u128));
        fields.insert("next_header".into(), Value::Int(next_header as u128));
        fields.insert("hop_limit".into(), Value::Int(hop_limit as u128));
        fields.insert("src".into(), Value::Ipv6(src));
        fields.insert("dst".into(), Value::Ipv6(dst));
        ctx.facts.net = Some(NetFacts::V6 {
            src,
            dst,
            next_header,
        });
        // Tranche 17a: the upper-layer packet begins right after the
        // fixed header (at the first extension header when one
        // follows). The L4 dissect-side verify reads this through
        // `DecodeCtx::frame`; equals the L4 layer's own offset on
        // every ext-free stack (pre-17a behavior identical).
        ctx.facts.upper_start = Some(ctx.offset + 40);
        let view = LayerView {
            kind: "ipv6",
            span: ctx.offset..ctx.offset + HEADER_LEN,
            field_spans: Default::default(),
            fields,
        };
        ReadOutcome::Layer(view, Some(Next::Kind(next_header_to_kind(next_header))))
    }

    /// Tranche 11b fixed layouts (40-byte header; the flow word's
    /// ver/tc/flow are bit windows of the first u32).
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
                "traffic_class",
                Layout::Bits {
                    at: 0,
                    shift: 4,
                    width: 8,
                },
            ),
            (
                "flow_label",
                Layout::Bits {
                    at: 0,
                    shift: 12,
                    width: 20,
                },
            ),
            ("payload_len", Layout::Bytes { at: 4, len: 2 }),
            ("next_header", Layout::Bytes { at: 6, len: 1 }),
            ("hop_limit", Layout::Bytes { at: 7, len: 1 }),
            ("src", Layout::Bytes { at: 8, len: 16 }),
            ("dst", Layout::Bytes { at: 24, len: 16 }),
        ]
    }

    /// `payload_len` = frame end − header end (RFC 8200: payload only,
    /// the 40-byte header excluded; no header checksum, §8.1). The
    /// tranche-14 sweep caught the old start-based formula here.
    fn derived(&self) -> &'static [Derived] {
        &[Derived::Length {
            field: "payload_len",
            at: 4,
            base: LengthBase::LayerEnd,
            units: LengthUnits::Bytes,
        }]
    }
}

#[cfg(feature = "test-util")]
pub mod strategy {
    //! proptest strategies for `LayerSpec` (behind `test-util`).
    use proptest::prelude::*;
    use wrex_core::spec::LayerSpec;
    use wrex_core::value::Value;

    /// Valid ipv6 specs: any flow word fields, addresses and hop limit;
    /// derived payload_len/next_header stay unset.
    pub fn strategy() -> BoxedStrategy<LayerSpec> {
        let ip6 = proptest::array::uniform16(any::<u8>())
            .prop_map(|o| Value::Ipv6(std::net::Ipv6Addr::from(o)));
        (
            any::<u8>(),
            (0u32..0x10_0000),
            any::<u8>(),
            ip6.clone(),
            ip6,
        )
            .prop_map(|(traffic_class, flow_label, hop_limit, src, dst)| {
                let mut fields = std::collections::BTreeMap::new();
                fields.insert(
                    "traffic_class".to_string(),
                    Value::Int(traffic_class as u128),
                );
                fields.insert("flow_label".to_string(), Value::Int(flow_label as u128));
                fields.insert("hop_limit".to_string(), Value::Int(hop_limit as u128));
                fields.insert("src".to_string(), src);
                fields.insert("dst".to_string(), dst);
                LayerSpec::with_fields("ipv6", fields)
            })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::BTreeMap;
    use wrex_core::Registry;
    use wrex_core::encode::{EncodeOpts, encode};
    use wrex_core::spec::PacketSpec;
    use wrex_core::value::parse_value;

    fn f(name: &str) -> &'static FieldSchema {
        SCHEMA.field(name).unwrap()
    }

    fn ip6_spec(fields: &[(&str, &str)]) -> LayerSpec {
        let mut map = BTreeMap::new();
        for (k, v) in fields {
            map.insert(k.to_string(), parse_value(f(k), v).unwrap());
        }
        LayerSpec::with_fields("ipv6", map)
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

    /// ADR 3: eth is a real parent dep, so this registers the actual
    /// eth codec through the `register()` closure and dissects a
    /// crafted eth→ipv6 frame end to end — the string dispatch table
    /// can no longer drift from the kinds it names (no stand-in).
    #[test]
    fn eth_dispatches_into_ipv6_with_real_codecs() {
        let mut r = wrex_core::Registry::empty();
        register(&mut r);
        let spec = wrex_core::spec::PacketSpec::new(
            vec![
                wrex_core::spec::LayerSpec::new(wrex_proto_eth::KIND),
                ip6_spec(&[]),
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
        // stacks inside ipv6 in this spec (children are the dispatch
        // direction — not linkable here), so next_header autofills to 0
        // and the synthetic layer carries the (empty) remainder.
        assert_eq!(
            p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
            vec![wrex_proto_eth::KIND, KIND, "unknown"],
            "eth.type 0x86dd must chain into the real ipv6 codec"
        );
    }

    #[test]
    fn golden_header_autofill() {
        let spec = ip6_spec(&[("src", "::1"), ("dst", "::1")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &af()).unwrap();
        assert_eq!(enc.bytes.len(), 40);
        assert_eq!(enc.bytes[0], 0x60); // ver 6, tc/flow zero
        assert_eq!(u16::from_be_bytes([enc.bytes[4], enc.bytes[5]]), 0); // payload_len
        assert_eq!(enc.bytes[6], 0); // next_header 0 (terminal)
        assert_eq!(enc.bytes[7], 64); // hop_limit
        let src: Ipv6Addr = "::1".parse().unwrap();
        assert_eq!(&enc.bytes[8..24], &src.octets()[..]); // src ::1
        let dst: Ipv6Addr = "::1".parse().unwrap();
        assert_eq!(&enc.bytes[24..40], &dst.octets()[..]);
    }

    #[test]
    fn payload_len_covers_appended_payload() {
        let spec = ip6_spec(&[]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(
                vec![spec],
                Some(Value::Bytes(Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]))),
            ),
            &af(),
        )
        .unwrap();
        assert_eq!(enc.bytes.len(), 44);
        assert_eq!(u16::from_be_bytes([enc.bytes[4], enc.bytes[5]]), 4);
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "ipv6");
        assert!(p.anomalies.is_empty(), "{:?}", p.anomalies);
        assert_eq!(p.layers[0].fields.get("payload_len"), Some(&Value::Int(4)));
    }

    #[test]
    fn flow_word_packing_and_masks() {
        let spec = ip6_spec(&[
            ("traffic_class", "0x2c"),
            ("flow_label", "0x12345"),
            ("hop_limit", "255"),
        ]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &af()).unwrap();
        // ver 6 | tc 0x2c | flow 0x12345 (20 bits kept)
        assert_eq!(
            u32::from_be_bytes([enc.bytes[0], enc.bytes[1], enc.bytes[2], enc.bytes[3]]),
            0x62c_12345
        );
        assert_eq!(enc.bytes[7], 255);
        // over-wide flow_label masks to 20 bits on read
        let mut p = [0u8; 40];
        p[0] = 0x60;
        p[3] = 0xff; // low 8 bits of a 20-bit flow
        let d = wrex_core::dissect::dissect(&registry(), &p, "ipv6");
        assert_eq!(
            d.layers[0].fields.get("flow_label"),
            Some(&Value::Int(0xff))
        );
    }

    #[test]
    fn explicit_wins_kept_unvalidated() {
        let spec = ip6_spec(&[
            ("ver", "5"), // deliberately invalid: kept
            ("payload_len", "999"),
            ("next_header", "99"),
        ]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts::default(),
        )
        .unwrap();
        assert_eq!(enc.bytes[0] >> 4, 5);
        assert_eq!(u16::from_be_bytes([enc.bytes[4], enc.bytes[5]]), 999);
        assert_eq!(enc.bytes[6], 99);
        assert!(enc.violations.is_empty());
    }

    #[test]
    fn truncation_anomaly() {
        let mut ctx = DecodeCtx::new(0);
        assert!(matches!(
            CODEC.read(&[0x60; 39], &mut ctx),
            ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: "ipv6",
                    need: 40,
                    have: 39
                },
                _
            )
        ));
        let mut ctx = DecodeCtx::new(0);
        assert!(matches!(CODEC.read(&[], &mut ctx), ReadOutcome::Empty));
    }

    #[test]
    fn payload_len_mismatch_anomaly() {
        let spec = ip6_spec(&[("payload_len", "9")]);
        let enc = encode(&registry(), &PacketSpec::new(vec![spec], None), &af()).unwrap();
        let p = wrex_core::dissect::dissect(&registry(), &enc.bytes, "ipv6");
        assert_eq!(p.layers[0].kind, "ipv6");
        assert!(
            p.anomalies.iter().any(|a| a.path == "ipv6.payload_len"),
            "{:?}",
            p.anomalies
        );
    }
}
