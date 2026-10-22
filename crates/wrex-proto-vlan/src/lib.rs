#![forbid(unsafe_code)]
//! wrex 802.1Q VLAN codec (pcp/dei/vid/type; rank 15, parents eth|vlan).
//! QinQ stacks: a vlan may follow eth (0x8100/0x88a8) or another vlan
//! (inner tag); craft always emits 0x8100 (0x88a8 dissect-only).

use std::sync::LazyLock;

use bytes::BufMut;

use wrex_core::dissect::LayerView;
use wrex_core::encode::{EncodeCtx, int_or_default};
use wrex_core::error::DecodeError;
use wrex_core::schema::{FieldKind, FieldSchema, LayerSchema, Layout};
use wrex_core::spec::LayerSpec;
use wrex_core::value::Value;
use wrex_core::{Codec, DecodeCtx, EncodeError, Next, ReadOutcome};

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
            "pcp",
            FieldKind::U8,
            "priority code point (0-7, 3 bits)",
            Value::Int(0),
        ),
        d(
            "dei",
            FieldKind::U8,
            "drop eligible indicator (0/1, 1 bit)",
            Value::Int(0),
        ),
        d(
            "vid",
            FieldKind::U16,
            "VLAN identifier (0-4095, 12 bits; 0 = priority tag)",
            Value::Int(0),
        ),
        d(
            "type",
            FieldKind::U16,
            "encapsulated ethertype (autofill: derived from next layer)",
            Value::Int(0),
        ),
    ]
});

/// The kind string this codec implements (ADR 3): children reference
/// `wrex_proto_vlan::KIND` in their `parents` instead of hand-written
/// strings, so the registry vocabulary is compile-checked.
pub const KIND: &str = "vlan";

pub static SCHEMA: LazyLock<LayerSchema> = LazyLock::new(|| LayerSchema {
    kind: KIND,
    rank: 15,
    parents: &[wrex_proto_eth::KIND, KIND],
    doc: "IEEE 802.1Q VLAN tag: 4-byte header (TCI: pcp 3 bits + dei 1 bit + vid 12 bits, then the encapsulated ethertype). Stacks on eth (or another vlan for QinQ/802.1ad double tagging; craft emits 0x8100, 0x88a8 is dissect-only). type drives the chain like eth.type: 0x0800 -> ipv4, 0x0806 -> arp, 0x86dd -> ipv6, 0x8100/0x88a8 -> vlan, else synthesized `unknown`.",
    fields: FIELDS.as_slice(),
    records: &[],
});

/// VLAN codec unit. Register via [`register`] (the ADR-3 closure);
/// bespoke registries may use `&wrex_proto_vlan::CODEC` directly.
pub struct VlanCodec;

pub static CODEC: VlanCodec = VlanCodec;

/// ADR 3 registration closure: register self (dedup-guarded via
/// [`Registry::get`]), then the parent crates' (the in-crate QinQ
/// self-parent needs no call). Self-first keeps `standard()`'s fixed
/// registration order byte-identical — presence, not order, is the
/// guarantee.
pub fn register(r: &mut wrex_core::Registry) {
    if r.get(KIND).is_none() {
        r.register(&CODEC);
    }
    wrex_proto_eth::register(r);
}

/// ethertype → next layer kind (for `read` continuation).
fn ethertype_to_kind(t: u16) -> &'static str {
    match t {
        0x0800 => "ipv4",
        0x0806 => "arp",
        0x86dd => "ipv6",
        0x8100 | 0x88a8 => "vlan",
        _ => "unknown",
    }
}

/// next layer kind → ethertype (for `write` autofill of `type`).
fn kind_to_ethertype(kind: Option<&'static str>) -> u16 {
    match kind {
        Some("ipv4") => 0x0800,
        Some("arp") => 0x0806,
        Some("ipv6") => 0x86dd,
        Some("vlan") => 0x8100,
        _ => 0x0000,
    }
}

impl Codec for VlanCodec {
    fn schema(&self) -> &'static LayerSchema {
        &SCHEMA
    }

    fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
        Ok(4)
    }

    fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
        let af = ctx.autofill;
        let pcp = int_or_default(spec, &FIELDS[0], af) as u8;
        let dei = int_or_default(spec, &FIELDS[1], af) as u8;
        let vid = int_or_default(spec, &FIELDS[2], af) as u16;
        let tci = ((pcp & 0x07) as u16) << 13 | ((dei & 0x01) as u16) << 12 | vid & 0x0fff;
        ctx.buf.put_u16(tci);
        let ethertype = match spec.fields.get("type") {
            Some(Value::Int(v)) => *v as u16,
            _ if ctx.autofill => kind_to_ethertype(ctx.next),
            _ => 0,
        };
        ctx.buf.put_u16(ethertype);
        Ok(())
    }

    fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
        if bytes.is_empty() {
            return ReadOutcome::Empty;
        }
        if bytes.len() < 4 {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: "vlan",
                    need: 4,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let tci = u16::from_be_bytes([bytes[0], bytes[1]]);
        let ethertype = u16::from_be_bytes([bytes[2], bytes[3]]);
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("pcp".into(), Value::Int((tci >> 13) as u128));
        fields.insert("dei".into(), Value::Int(((tci >> 12) & 1) as u128));
        fields.insert("vid".into(), Value::Int((tci & 0x0fff) as u128));
        fields.insert("type".into(), Value::Int(ethertype as u128));
        let view = LayerView {
            kind: "vlan",
            span: ctx.offset..ctx.offset + 4,
            field_spans: Default::default(),
            fields,
        };
        ReadOutcome::Layer(view, Some(Next::Kind(ethertype_to_kind(ethertype))))
    }

    /// Tranche 11b fixed layouts: TCI bit windows (pcp/dei/vid pack the
    /// first u16 MSB-first) + the encapsulated ethertype.
    fn layouts(&self) -> &'static [(&'static str, Layout)] {
        &[
            (
                "pcp",
                Layout::Bits {
                    at: 0,
                    shift: 0,
                    width: 3,
                },
            ),
            (
                "dei",
                Layout::Bits {
                    at: 0,
                    shift: 3,
                    width: 1,
                },
            ),
            (
                "vid",
                Layout::Bits {
                    at: 0,
                    shift: 4,
                    width: 12,
                },
            ),
            ("type", Layout::Bytes { at: 2, len: 2 }),
        ]
    }
}

#[cfg(feature = "test-util")]
pub mod strategy {
    //! proptest strategies for `LayerSpec` (behind `test-util`).
    use proptest::prelude::*;
    use wrex_core::spec::LayerSpec;
    use wrex_core::value::Value;

    /// Valid vlan specs: pcp 0-7, dei 0/1, vid 0-4095; type among known
    /// and arbitrary values (self-chaining 8100/88a8 excluded: a random
    /// inner tag would recurse past the spec's stack; 86dd excluded
    /// since tranche 7b — a random ipv6 ethertype on a v4 stack
    /// mis-parses the chain, the dedicated ipv6 stacks cover it).
    ///
    /// Derived type stays unset (QinQ inner chains derive it via
    /// --layer autofill).
    pub fn strategy() -> BoxedStrategy<LayerSpec> {
        (
            0u8..8,
            proptest::bool::ANY,
            0u16..4096,
            proptest::option::of(
                proptest::sample::select(vec![0x0800u16, 0x0806, 0x1234])
                    .prop_map(|v| Value::Int(v as u128)),
            ),
        )
            .prop_map(|(pcp, dei, vid, ty)| {
                let mut fields = std::collections::BTreeMap::new();
                fields.insert("pcp".to_string(), Value::Int(pcp as u128));
                fields.insert("dei".to_string(), Value::Int(dei as u128));
                fields.insert("vid".to_string(), Value::Int(vid as u128));
                if let Some(t) = ty {
                    fields.insert("type".to_string(), t);
                }
                LayerSpec::with_fields("vlan", fields)
            })
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

    fn vlan_spec(fields: &[(&str, &str)]) -> LayerSpec {
        let mut map = BTreeMap::new();
        for (k, v) in fields {
            map.insert(k.to_string(), parse_value(f(k), v).unwrap());
        }
        LayerSpec::with_fields("vlan", map)
    }

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

    /// ADR 3: eth is a real parent dep, so this registers the actual
    /// eth codec through the `register()` closure and dissects a
    /// crafted eth→vlan frame end to end — the string dispatch table
    /// can no longer drift from the kinds it names (no stand-in).
    #[test]
    fn eth_dispatches_into_vlan_with_real_codecs() {
        let mut r = wrex_core::Registry::empty();
        register(&mut r);
        let spec = wrex_core::spec::PacketSpec::new(
            vec![
                wrex_core::spec::LayerSpec::new(wrex_proto_eth::KIND),
                vlan_spec(&[("vid", "100")]),
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
        // stacks inside vlan in this spec, so vlan.type autofills to 0
        // and the synthetic layer carries the (empty) remainder.
        assert_eq!(
            p.layers.iter().map(|l| l.kind).collect::<Vec<_>>(),
            vec![wrex_proto_eth::KIND, KIND, "unknown"],
            "eth.type 0x8100 must chain into the real vlan codec"
        );
    }

    #[test]
    fn golden_explicit_tci() {
        let spec = vlan_spec(&[
            ("pcp", "3"),
            ("dei", "1"),
            ("vid", "100"),
            ("type", "0x0800"),
        ]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts::default(),
        )
        .unwrap();
        // pcp 3 << 13 | dei 1 << 12 | vid 100 = 0x6000 | 0x1000 | 0x64
        assert_eq!(&enc.bytes[..], &[0x70, 0x64, 0x08, 0x00][..]);
    }

    /// A schema-only ipv4 codec so the next-kind derivation test can run
    /// without cross-crate proto dependencies (same pattern as eth).
    struct MockIp;
    static MOCK_IP_FIELDS: LazyLock<Vec<FieldSchema>> = LazyLock::new(Vec::new);
    static MOCK_IP_SCHEMA: LazyLock<LayerSchema> = LazyLock::new(|| LayerSchema {
        kind: "ipv4",
        rank: 20,
        parents: &["eth", "vlan"],
        doc: "test stand-in",
        fields: MOCK_IP_FIELDS.as_slice(),
        records: &[],
    });
    impl Codec for MockIp {
        fn schema(&self) -> &'static LayerSchema {
            &MOCK_IP_SCHEMA
        }
        fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
            Ok(20)
        }
        fn write(&self, _spec: &LayerSpec, _ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
            Ok(())
        }
        fn read<'a>(&self, _b: &'a [u8], _c: &mut DecodeCtx<'a>) -> ReadOutcome {
            ReadOutcome::Empty
        }
    }
    static MOCK_IP: MockIp = MockIp;

    #[test]
    fn autofill_type_derives_next_and_zeros_tci() {
        let mut reg = registry();
        reg.register(&MOCK_IP);
        let ps = PacketSpec::new(vec![vlan_spec(&[]), LayerSpec::new("ipv4")], None);
        let enc = encode(&reg, &ps, &opts()).unwrap();
        // no explicit fields: tci 0, type derived from ipv4
        assert_eq!(&enc.bytes[..], &[0x00, 0x00, 0x08, 0x00][..]);
        // no-autofill: type 0
        let enc2 = encode(&reg, &ps, &EncodeOpts::default()).unwrap();
        assert_eq!(u16::from_be_bytes([enc2.bytes[2], enc2.bytes[3]]), 0x0000);
    }

    #[test]
    fn read_golden_and_chain() {
        let bytes = [0xa8, 0x64, 0x08, 0x00]; // tci 0xa864: pcp 5, dei 0, vid 0x864
        let mut ctx = DecodeCtx::new(0);
        match CODEC.read(&bytes, &mut ctx) {
            ReadOutcome::Layer(view, Some(Next::Kind(next))) => {
                assert_eq!(view.kind, "vlan");
                assert_eq!(view.span, 0..4);
                assert_eq!(next, "ipv4");
                assert_eq!(view.fields.get("pcp"), Some(&Value::Int(5)));
                assert_eq!(view.fields.get("dei"), Some(&Value::Int(0)));
                assert_eq!(view.fields.get("vid"), Some(&Value::Int(0x864)));
                assert_eq!(view.fields.get("type"), Some(&Value::Int(0x0800)));
            }
            other => panic!("expected layer, got {other:?}"),
        }
    }

    #[test]
    fn qinq_ethertypes_chain_into_vlan() {
        for t in [0x8100u16, 0x88a8] {
            let bytes = [0x00, 0x64, (t >> 8) as u8, t as u8];
            let mut ctx = DecodeCtx::new(0);
            match CODEC.read(&bytes, &mut ctx) {
                ReadOutcome::Layer(_, Some(Next::Kind(next))) => assert_eq!(next, "vlan"),
                other => panic!("expected layer, got {other:?}"),
            }
        }
    }

    #[test]
    fn unknown_ethertype_marks_unknown() {
        let bytes = [0x00, 0x64, 0x12, 0x34];
        let mut ctx = DecodeCtx::new(0);
        match CODEC.read(&bytes, &mut ctx) {
            ReadOutcome::Layer(_, Some(Next::Kind(next))) => assert_eq!(next, "unknown"),
            other => panic!("expected layer, got {other:?}"),
        }
    }

    #[test]
    fn truncation_anomaly() {
        let mut ctx = DecodeCtx::new(0);
        match CODEC.read(&[0x00, 0x64, 0x08], &mut ctx) {
            ReadOutcome::Anomaly(DecodeError::Truncated { kind, need, have }, _) => {
                assert_eq!((kind, need, have), ("vlan", 4, 3));
            }
            other => panic!("expected anomaly, got {other:?}"),
        }
        assert!(ctx.anomalies.is_empty());
    }

    #[test]
    fn empty_input() {
        let mut ctx = DecodeCtx::new(0);
        assert!(matches!(CODEC.read(&[], &mut ctx), ReadOutcome::Empty));
    }

    #[test]
    fn vid_value_wider_than_12_bits_kept_on_write() {
        // explicit values are kept unvalidated (deliberate-invalid feature):
        // 0x1234 vid wraps to 12 bits on the wire.
        let spec = vlan_spec(&[("vid", "0x1234")]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts::default(),
        )
        .unwrap();
        assert_eq!(u16::from_be_bytes([enc.bytes[0], enc.bytes[1]]), 0x0234);
    }
}
