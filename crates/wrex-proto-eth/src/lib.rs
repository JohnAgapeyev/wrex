#![forbid(unsafe_code)]
//! wrex Ethernet II codec (dst/src/type, rank 10, no parents).

use std::sync::LazyLock;

use bytes::BufMut;

use wrex_core::dissect::LayerView;
use wrex_core::encode::{EncodeCtx, mac_or_default};
use wrex_core::error::DecodeError;
use wrex_core::schema::{FieldKind, FieldSchema, LayerSchema};
use wrex_core::spec::LayerSpec;
use wrex_core::value::Value;
use wrex_core::{Codec, DecodeCtx, EncodeError, Next, ReadOutcome};

static FIELDS: LazyLock<Vec<FieldSchema>> = LazyLock::new(|| {
    vec![
        FieldSchema {
            name: "dst",
            kind: FieldKind::Mac,
            bit_names: &[],
            default: Value::Mac([0xff; 6]),
            required: false,
            doc: "destination MAC (autofill: ff:ff:ff:ff:ff:ff)",
        },
        FieldSchema {
            name: "src",
            kind: FieldKind::Mac,
            bit_names: &[],
            default: Value::Mac([0; 6]),
            required: false,
            doc: "source MAC (autofill: interface MAC on send)",
        },
        FieldSchema {
            name: "type",
            kind: FieldKind::U16,
            bit_names: &[],
            default: Value::Int(0),
            required: false,
            doc: "ethertype (autofill: derived from next layer)",
        },
    ]
});

pub static SCHEMA: LazyLock<LayerSchema> = LazyLock::new(|| LayerSchema {
    kind: "eth",
    rank: 10,
    parents: &[],
    fields: FIELDS.as_slice(),
});

/// Ethernet II codec unit. Register as `&wrex_proto_eth::CODEC`.
pub struct EthCodec;

pub static CODEC: EthCodec = EthCodec;

/// ethertype → next layer kind (for `read` continuation).
fn ethertype_to_kind(t: u16) -> &'static str {
    match t {
        0x0800 => "ipv4",
        0x0806 => "arp",
        // Everything else (incl. 0x86dd ipv6, unsupported this tranche):
        // the engine synthesizes an `unknown` layer for the remainder.
        _ => "unknown",
    }
}

/// next layer kind → ethertype (for `write` derivation).
fn kind_to_ethertype(kind: Option<&'static str>) -> u16 {
    match kind {
        Some("ipv4") => 0x0800,
        Some("arp") => 0x0806,
        _ => 0x0000,
    }
}

impl Codec for EthCodec {
    fn schema(&self) -> &'static LayerSchema {
        &SCHEMA
    }

    fn header_len(&self, _spec: &LayerSpec) -> Result<usize, EncodeError> {
        Ok(14)
    }

    fn write(&self, spec: &LayerSpec, ctx: &mut EncodeCtx) -> Result<(), EncodeError> {
        let dst = mac_or_default(spec, &FIELDS[0], ctx.autofill, [0; 6]);
        // src prefers the interface MAC from caller-seeded facts (send -i).
        let src = match spec.fields.get("src") {
            Some(Value::Mac(m)) => *m,
            _ => match (ctx.autofill, ctx.facts.link_src) {
                (true, Some(m)) => m,
                _ => [0; 6],
            },
        };
        let ethertype = match spec.fields.get("type") {
            Some(Value::Int(v)) => *v as u16,
            _ if ctx.autofill => kind_to_ethertype(ctx.next),
            _ => 0,
        };
        ctx.buf.extend_from_slice(&dst);
        ctx.buf.extend_from_slice(&src);
        ctx.buf.put_u16(ethertype);
        Ok(())
    }

    fn read<'a>(&self, bytes: &'a [u8], ctx: &mut DecodeCtx<'a>) -> ReadOutcome {
        if bytes.is_empty() {
            return ReadOutcome::Empty;
        }
        if bytes.len() < 14 {
            return ReadOutcome::Anomaly(
                DecodeError::Truncated {
                    kind: "eth",
                    need: 14,
                    have: bytes.len(),
                },
                Next::Payload,
            );
        }
        let mut dst = [0u8; 6];
        dst.copy_from_slice(&bytes[0..6]);
        let mut src = [0u8; 6];
        src.copy_from_slice(&bytes[6..12]);
        let ethertype = u16::from_be_bytes([bytes[12], bytes[13]]);
        let mut fields = std::collections::BTreeMap::new();
        fields.insert("dst".into(), Value::Mac(dst));
        fields.insert("src".into(), Value::Mac(src));
        fields.insert("type".into(), Value::Int(ethertype as u128));
        let view = LayerView {
            kind: "eth",
            span: ctx.offset..ctx.offset + 14,
            fields,
        };
        ReadOutcome::Layer(view, Some(Next::Kind(ethertype_to_kind(ethertype))))
    }
}

#[cfg(feature = "test-util")]
pub mod strategy {
    //! proptest strategies for `LayerSpec` (behind `test-util`).
    use proptest::prelude::*;
    use wrex_core::spec::LayerSpec;
    use wrex_core::value::Value;

    /// Valid eth specs: any MACs, ethertype among known + arbitrary values.
    pub fn strategy() -> BoxedStrategy<LayerSpec> {
        let mac = proptest::array::uniform6(any::<u8>()).prop_map(Value::Mac);
        let ty = proptest::option::of(
            proptest::sample::select(vec![0x0800u16, 0x0806, 0x86dd, 0x1234])
                .prop_map(|v| Value::Int(v as u128)),
        );
        (mac.clone(), mac, ty)
            .prop_map(|(dst, src, ty)| {
                let mut fields = std::collections::BTreeMap::new();
                fields.insert("dst".to_string(), dst);
                fields.insert("src".to_string(), src);
                if let Some(t) = ty {
                    fields.insert("type".to_string(), t);
                }
                LayerSpec::with_fields("eth", fields)
            })
            .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use wrex_core::dissect::DecodeCtx;
    use wrex_core::encode::{EncodeOpts, encode};
    use wrex_core::spec::PacketSpec;
    use wrex_core::value::parse_value;
    use wrex_core::{Codec, Next, ReadOutcome, Registry};

    fn f(name: &str) -> &'static FieldSchema {
        SCHEMA.field(name).unwrap()
    }

    fn eth_spec(fields: &[(&str, &str)]) -> LayerSpec {
        let mut map = BTreeMap::new();
        for (k, v) in fields {
            map.insert(k.to_string(), parse_value(f(k), v).unwrap());
        }
        LayerSpec::with_fields("eth", map)
    }

    fn registry() -> Registry {
        let mut r = Registry::empty();
        r.register(&CODEC);
        r
    }

    #[test]
    fn golden_explicit() {
        let spec = eth_spec(&[
            ("dst", "ff:ff:ff:ff:ff:ff"),
            ("src", "00:11:22:33:44:55"),
            ("type", "0x0800"),
        ]);
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![spec], None),
            &EncodeOpts::default(),
        )
        .unwrap();
        assert_eq!(
            &enc.bytes[..],
            &[
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00
            ][..]
        );
    }

    #[test]
    fn autofill_table() {
        // terminal eth, no explicit fields: dst ff.. src 00.. type 0x0000
        let enc = encode(
            &registry(),
            &PacketSpec::new(vec![eth_spec(&[])], None),
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut want = vec![0xff; 6];
        want.extend_from_slice(&[0; 6]);
        want.extend_from_slice(&[0x00, 0x00]);
        assert_eq!(&enc.bytes[..], &want[..]);
    }

    /// A schema-only ipv4 codec so eth tests can exercise next-kind
    /// derivation without cross-crate proto dependencies.
    struct MockIp;
    static MOCK_IP_FIELDS: LazyLock<Vec<FieldSchema>> = LazyLock::new(|| {
        vec![FieldSchema {
            name: "ttl",
            kind: FieldKind::U8,
            bit_names: &[],
            default: Value::Int(64),
            required: false,
            doc: "",
        }]
    });
    static MOCK_IP_SCHEMA: LazyLock<LayerSchema> = LazyLock::new(|| LayerSchema {
        kind: "ipv4",
        rank: 20,
        parents: &["eth"],
        fields: MOCK_IP_FIELDS.as_slice(),
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
    fn autofill_next_derivation() {
        let mut r = registry();
        r.register(&MOCK_IP);
        // eth → ipv4(mock): eth.type derives 0x0800
        let ps = PacketSpec::new(vec![eth_spec(&[]), LayerSpec::new("ipv4")], None);
        let enc = encode(
            &r,
            &ps,
            &EncodeOpts {
                autofill: true,
                ..Default::default()
            },
        )
        .unwrap();
        let mut want = vec![0xff; 6];
        want.extend_from_slice(&[0; 6]);
        want.extend_from_slice(&[0x08, 0x00]);
        assert_eq!(&enc.bytes[..14], &want[..]);
        assert_eq!(u16::from_be_bytes([enc.bytes[12], enc.bytes[13]]), 0x0800);
        // no-autofill: type 0
        let enc2 = encode(&r, &ps, &EncodeOpts::default()).unwrap();
        assert_eq!(u16::from_be_bytes([enc2.bytes[12], enc2.bytes[13]]), 0x0000);
    }

    #[test]
    fn truncation_anomaly() {
        let mut ctx = DecodeCtx::new(0);
        match CODEC.read(&[0xff; 13], &mut ctx) {
            ReadOutcome::Anomaly(DecodeError::Truncated { kind, need, have }, _) => {
                assert_eq!((kind, need, have), ("eth", 14, 13));
            }
            other => panic!("expected anomaly, got {other:?}"),
        }
        assert!(ctx.anomalies.is_empty());
    }

    #[test]
    fn read_golden_and_chain() {
        let bytes = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
        ];
        let mut ctx = DecodeCtx::new(3);
        match CODEC.read(&bytes, &mut ctx) {
            ReadOutcome::Layer(view, Some(Next::Kind(next))) => {
                assert_eq!(view.kind, "eth");
                assert_eq!(view.span, 3..17);
                assert_eq!(next, "ipv4");
                assert_eq!(view.fields.get("type"), Some(&Value::Int(0x0800)));
            }
            other => panic!("expected layer, got {other:?}"),
        }
        // unknown ethertype → `unknown` kind for the engine to synthesize
        let mut ctx = DecodeCtx::new(0);
        let odd = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x12, 0x34,
        ];
        match CODEC.read(&odd, &mut ctx) {
            ReadOutcome::Layer(_, Some(Next::Kind(next))) => assert_eq!(next, "unknown"),
            other => panic!("expected layer, got {other:?}"),
        }
    }

    #[test]
    fn empty_input() {
        let mut ctx = DecodeCtx::new(0);
        assert!(matches!(CODEC.read(&[], &mut ctx), ReadOutcome::Empty));
    }
}
